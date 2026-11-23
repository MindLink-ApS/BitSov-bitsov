//! Node-routed call signalling and sequential paid 60-second blocks.
//! Media travels app → own node → peer node → peer app. Only paid block
//! settlement admits media; an answer starts a thirty-second payment window.
//! Durable reservations, bounded call ids and replay tombstones survive restarts.

use serde::{Deserialize, Serialize};

use crate::kind::{KIND_CALL_ANSWER, KIND_CALL_BLOCK, KIND_CALL_HANGUP, KIND_CALL_INVITE, KIND_ICE_CANDIDATE};
use crate::types::NodeId;

/// Payload schema version.
pub const CALL_SIGNAL_VERSION: u8 = 1;
/// Largest SDP accepted in an offer or answer.
pub const MAX_SDP_BYTES: usize = 16 * 1024;
/// Largest single ICE candidate line.
pub const MAX_CANDIDATE_BYTES: usize = 1024;
/// How long a callee waits for a paired device to take an invite.
pub const DEVICE_WAIT_MS: u64 = 15_000;
/// How long an unanswered offer rings.
pub const RING_TIMEOUT_MS: u64 = 60_000;
/// Oldest offer (by its envelope timestamp, on the callee's clock) a callee
/// still rings: covers payment, routing and resend delay.
pub const INVITE_MAX_AGE_MS: u64 = 30_000;
/// Clock difference between two nodes the call timing tolerates.
pub const CALL_CLOCK_SKEW_MS: u64 = 15_000;
/// Allowance for the callee's answer to reach the caller.
pub const ANSWER_TRANSIT_MS: u64 = 15_000;
/// Longest device stream write. One armed before the device deadline still
/// counts as delivery and rings from its completion, at most this late.
pub const DEVICE_WRITE_TIMEOUT_MS: u64 = 2_000;
/// The caller's answer window from payment. A callee rings an offer only if
/// it arrives within [`INVITE_MAX_AGE_MS`] of the offer's timestamp (taken no
/// later than payment, never renewed), waits at most [`DEVICE_WAIT_MS`] for a
/// device (whose stream write may finish up to [`DEVICE_WRITE_TIMEOUT_MS`]
/// later), then rings for [`RING_TIMEOUT_MS`]; its last answer still needs
/// transit and may be off by the clock skew. So every answer the callee may
/// send in its window reaches the caller inside this one.
pub const CALLER_ANSWER_WINDOW_MS: u64 = INVITE_MAX_AGE_MS
    + CALL_CLOCK_SKEW_MS
    + DEVICE_WAIT_MS
    + DEVICE_WRITE_TIMEOUT_MS
    + RING_TIMEOUT_MS
    + ANSWER_TRANSIT_MS;

/// Whether a callee may still ring an offer stamped `offer_ms` that arrived at
/// `arrived_ms` (callee clock): not older than [`INVITE_MAX_AGE_MS`], and not
/// from further in the future than the tolerated skew.
pub fn invite_fresh(offer_ms: u64, arrived_ms: u64) -> bool {
    arrived_ms <= offer_ms.saturating_add(INVITE_MAX_AGE_MS)
        && offer_ms <= arrived_ms.saturating_add(CALL_CLOCK_SKEW_MS)
}
/// Length of a paid media interval.
pub const CALL_BLOCK_MS: u64 = 60_000;
/// Renewal is due this long before the paid interval ends.
pub const CALL_BLOCK_LEAD_MS: u64 = 20_000;
/// Late payment slack after a paid interval.
pub const CALL_BLOCK_GRACE_MS: u64 = 10_000;
/// Block zero gets the same lead plus grace as a renewal, without media.
pub const CALL_BLOCK_INITIAL_MS: u64 = CALL_BLOCK_LEAD_MS + CALL_BLOCK_GRACE_MS;
/// Refuse new invoices with less time left (deadline already includes grace).
pub const CALL_BLOCK_INVOICE_MARGIN_MS: u64 = 15_000;
/// A settled next block may resume an Unpaid call for this long after its end.
pub const CALL_BLOCK_RESUME_MS: u64 = 60_000;
/// Short BOLT11 lifetime; in-flight HTLCs and LDK's inbound buffer can outlive it.
pub const CALL_BLOCK_INVOICE_EXPIRY_SECS: u32 = 5;
/// Invoice requests carry the call and sequence so the callee checks its clock.
pub const CALL_BLOCK_INVOICE_PREFIX: &str = "konsensus:call_block:";
/// Maximum outstanding invoice bindings per peer, call and block sequence.
/// Refuse further issuance without evicting a hash that may already be paid.
pub const MAX_CALL_BLOCK_INVOICES: u32 = 8;
/// Largest amount a peer may name on a call-block invoice request: 1 BTC.
/// The same ceiling an owner invoice uses. Zero is not an amount.
pub const MAX_CALL_BLOCK_INVOICE_MSAT: u64 = 100_000_000_000;
/// Longest continuously paid call.
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

/// A node advertising this accepts, at no charge, the answer and the declined
/// hangup that reply to its own ringing offer (see [`is_free_reply_shape`]).
pub const FREE_REPLY_CAPABILITY: &str = "call_reply_free_v1";

/// A node advertising this issues call-bound hangup invoices: a hangup for a
/// live call is paid only through an invoice the recipient issued for that
/// call after checking it is still live (see [`hangup_invoice_purpose`]).
pub const HANGUP_INVOICE_CAPABILITY: &str = "call_hangup_invoice_v1";
/// Invoice requests for a call-bound hangup: `konsensus:call_hangup:<call_id>:<sender side>`.
pub const CALL_HANGUP_INVOICE_PREFIX: &str = "konsensus:call_hangup:";
/// The binding slot a hangup invoice takes in the call invoice bindings. It is
/// past every block sequence a call can reach, so a hangup invoice can never
/// buy a block and a block invoice can never pay a bound hangup.
pub const HANGUP_INVOICE_SEQ: u32 = u32::MAX;

/// The invoice purpose for a hangup of `call_id` sent by the `sender` side.
pub fn hangup_invoice_purpose(call_id: &str, sender: Side) -> String {
    format!("{CALL_HANGUP_INVOICE_PREFIX}{call_id}:{}", sender.as_str())
}

/// The call id and sender side a hangup invoice request names. `None` for any
/// other purpose, including a malformed hangup purpose.
pub fn parse_hangup_invoice_purpose(purpose: &str) -> Option<(String, Side)> {
    let (call_id, side) = purpose.strip_prefix(CALL_HANGUP_INVOICE_PREFIX)?.split_once(':')?;
    (is_call_id(call_id)).then_some(())?;
    Some((call_id.to_owned(), Side::parse(side)?))
}

/// Whether this hangup goes through a call-bound invoice: an ordinary end of
/// a call this node holds live. End notices for a call that is already over
/// (`unpaid`, `duration_cap`) and replies to a ringing call keep their paths.
pub fn hangup_uses_invoice(entry: Option<&CallEntry>, reason: Option<HangupReason>) -> bool {
    !matches!(reason, Some(HangupReason::Unpaid | HangupReason::DurationCap))
        && entry.is_some_and(|e| e.phase == Phase::Live)
}

/// The recipient's check before it issues a hangup invoice: its own row for
/// this call (already passed through [`CallEntry::at`]) is live and on the
/// other side from the sender. Anything else means the call is over here and
/// no invoice is issued, so nothing is paid.
pub fn validate_hangup_invoice(entry: Option<&CallEntry>, sender: Side) -> Result<(), CallRefusal> {
    match entry {
        Some(e) if e.side == sender => Err(CallRefusal::WrongSide),
        Some(e) if e.phase == Phase::Live => Ok(()),
        _ => Err(CallRefusal::UnknownCall),
    }
}

/// The single reference a free reply carries: it names the call it answers
/// without revealing the call id outside the encrypted payload.
pub fn free_reply_reference(call_id: &str) -> crate::types::MessageId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bitsov call free reply v1\0");
    hasher.update(call_id.as_bytes());
    crate::types::MessageId::from_bytes(*hasher.finalize().as_bytes())
}

/// Whether `envelope` is shaped as a free call reply: an answer or a hangup,
/// carrying no payment (amount zero) and exactly one reference. The shape
/// alone grants nothing: the receiving node accepts it only against its own
/// ringing offer to that sender, and checks the payload after decryption.
pub fn is_free_reply_shape(envelope: &crate::envelope::UkmEnvelope) -> bool {
    matches!(envelope.kind, KIND_CALL_ANSWER | KIND_CALL_HANGUP)
        && envelope.payment_proof.amount_msat == 0
        && envelope.references.len() == 1
}

/// What media an offer asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallMedia {
    Audio,
    Video,
}

fn signal_version() -> u8 { CALL_SIGNAL_VERSION }

/// The JSON inside a 400-404 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSignal {
    #[serde(default = "signal_version")]
    pub v: u8,
    /// 32 lowercase hex characters (16 random bytes), chosen by the caller.
    pub call_id: String,
    /// 404 only: strictly sequential, starting at zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u32>,
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
    Unpaid,
    #[serde(rename = "duration_cap")]
    DurationCap,
}

impl HangupReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hangup => "hangup", Self::Declined => "declined", Self::Busy => "busy",
            Self::Timeout => "timeout", Self::Failed => "failed", Self::Unpaid => "unpaid", Self::DurationCap => "duration_cap",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "hangup" => Some(Self::Hangup), "declined" => Some(Self::Declined), "busy" => Some(Self::Busy),
            "timeout" => Some(Self::Timeout), "failed" => Some(Self::Failed), "unpaid" => Some(Self::Unpaid), "duration_cap" => Some(Self::DurationCap), _ => None,
        }
    }
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
    #[error("call block sequence is duplicated or out of order")]
    Sequence,
    #[error("call block is not due yet")]
    NotDue,
    /// The callee cannot ring this offer inside the caller's answer window.
    #[error("call_not_reachable")]
    NotReachable,
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
        if !(KIND_CALL_INVITE..=KIND_CALL_BLOCK).contains(&kind) {
            return Err(CallRefusal::NotCallKind);
        }
        if plaintext.len() > MAX_SDP_BYTES + 1024 {
            return Err(CallRefusal::Invalid("payload too large"));
        }
        let s: CallSignal = crate::wire_json::from_str(plaintext).map_err(|_| CallRefusal::Invalid("not a call signal"))?;
        if kind != KIND_CALL_BLOCK && !crate::wire_json::from_str::<serde_json::Value>(plaintext).is_ok_and(|v| v.get("v").is_some()) {
            return Err(CallRefusal::Invalid("missing version"));
        }
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
        let ok = (kind == KIND_CALL_BLOCK || s.seq.is_none()) && match kind {
            KIND_CALL_INVITE => {
                s.media.is_some() && sdp_ok(&s.sdp) && none_but(true, true, false, false) && s.meeting.as_ref().is_none_or(Meeting::valid)
            }
            KIND_CALL_ANSWER => sdp_ok(&s.sdp) && none_but(false, true, false, false),
            KIND_ICE_CANDIDATE => {
                s.candidate.as_deref().is_some_and(|c| c.len() <= MAX_CANDIDATE_BYTES)
                    && s.sdp_mid.as_deref().is_none_or(|m| m.len() <= 64)
                    && none_but(false, false, true, false)
            }
            KIND_CALL_BLOCK => s.seq.is_some() && none_but(false, false, false, false),
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
    /// An incoming offer has not yet reached one of our devices.
    AwaitingDevice,
    Ringing,
    Live,
    Ended,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self { Phase::Reserved => "reserved", Phase::AwaitingDevice => "awaiting_device", Phase::Ringing => "ringing", Phase::Live => "live", Phase::Ended => "ended" }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reserved" => Some(Phase::Reserved),
            "awaiting_device" => Some(Phase::AwaitingDevice),
            "ringing" => Some(Phase::Ringing),
            "live" => Some(Phase::Live),
            "ended" => Some(Phase::Ended),
            _ => None,
        }
    }
}

/// One of our own signals, reserved under its operation id and not yet paid.
/// Bound to the exact request (`request_hash`, the operation journal's
/// digest), so a concurrent request sharing the operation id but carrying
/// another payload never shares, commits or releases it (review delta2 #2).
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

/// At most this many free-reply receipts on one call row. A free reply moves
/// its call out of ringing, so a row normally holds one; a full set refuses
/// another transition instead of dropping a receipt.
pub const MAX_FREE_REPLY_RECEIPTS: usize = 4;

/// Durable proof that one saved free reply (answer or decline) moved its call.
/// Written in the same call-row write as the transition it certifies, so a
/// reply saved before that write can tell, after any stop, whether its own
/// transition happened. Bound to the exact peer, call, reply kind, operation
/// and request digest; a matching phase alone proves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeReplyReceipt {
    /// The peer, as hex.
    pub peer: String,
    pub call_id: String,
    pub kind: u16,
    pub operation_id: String,
    /// The operation journal's request digest; never empty.
    pub request_hash: String,
    /// The phase the reply moved the call to.
    #[serde(default)]
    pub phase: String,
    /// When the transition was applied.
    #[serde(default)]
    pub applied_ms: u64,
}

impl FreeReplyReceipt {
    /// The same operation, request, peer, call and kind as `other`.
    pub fn binds(&self, other: &FreeReplyReceipt) -> bool {
        self.peer == other.peer && self.call_id == other.call_id && self.kind == other.kind
            && self.operation_id == other.operation_id && self.request_hash == other.request_hash
    }
}

/// The state of one `(peer, call_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEntry {
    pub side: Side,
    pub phase: Phase,
    /// End of ringing / live, or of the replay tombstone once ended.
    pub deadline_ms: u64,
    pub pending: Option<Pending>,
    /// Last paid boundary; absent until block zero settles.
    /// Zero on a callee closes resume, including while awaiting expiry.
    pub paid_until_ms: Option<u64>,
    pub next_block_seq: u32,
    pub end_reason: Option<HangupReason>,
    /// Unpaid notice received (caller) or reserved/sent (callee). Survives restart.
    pub unpaid_notice_used: bool,
    /// Free replies whose transition moved this call, kept until their saved
    /// reply can no longer be recovered. Rows written before receipts existed
    /// have none. A row holding one is never aged out or evicted.
    pub free_reply_receipts: Vec<FreeReplyReceipt>,
}

impl CallEntry {
    /// Media fails closed until a block is paid, and immediately after grace.
    pub fn media_admitted(&self, now_ms: u64) -> bool {
        self.phase == Phase::Live && self.paid_until_ms.is_some_and(|until| now_ms <= until.saturating_add(CALL_BLOCK_GRACE_MS))
    }

    /// The caller schedules this sequence through authenticated compose.
    pub fn next_block_due_ms(&self) -> Option<u64> {
        (self.phase == Phase::Live && u64::from(self.next_block_seq) < MAX_CALL_MS / CALL_BLOCK_MS).then(|| {
            self.paid_until_ms.map_or(self.deadline_ms.saturating_sub(CALL_BLOCK_INITIAL_MS), |until| until.saturating_sub(CALL_BLOCK_LEAD_MS))
        })
    }

    fn answered(self, now_ms: u64) -> Self {
        Self { phase: Phase::Live, deadline_ms: now_ms.saturating_add(CALL_BLOCK_INITIAL_MS), ..self }
    }

    fn expired(&self, now_ms: u64) -> bool {
        if self.phase == Phase::Live { now_ms > self.deadline_ms } else { now_ms >= self.deadline_ms }
    }

    /// Until when this id must stay burned (the row may not be dropped before).
    pub fn replay_until_ms(&self) -> u64 {
        match self.phase {
            Phase::Ended => self.deadline_ms,
            _ => self.deadline_ms.saturating_add(TOMBSTONE_MS),
        }
    }

    /// The entry as of `now_ms`: a ringing/live/reserved call past its deadline
    /// is ended (its tombstone runs from the deadline); an expired tombstone is
    /// gone. Pending caller blocks survive only the bounded Unpaid resume
    /// window; payment reconciliation lives independently in the outbox journal.
    pub fn at(self, now_ms: u64) -> Option<CallEntry> {
        match self.phase {
            Phase::Ended if self.deadline_ms <= now_ms && self.free_reply_receipts.is_empty() && (self.pending.is_none()
                || (self.side == Side::Caller && self.pending.as_ref().is_some_and(|p| p.kind == KIND_CALL_BLOCK))) => None,
            Phase::Ended if self.side == Side::Caller
                && self.pending.as_ref().is_some_and(|p| p.kind == KIND_CALL_BLOCK)
                && (self.end_reason != Some(HangupReason::Unpaid)
                || now_ms > self.deadline_ms.saturating_sub(TOMBSTONE_MS).saturating_add(CALL_BLOCK_RESUME_MS)) => {
                Some(CallEntry { pending: None, ..self })
            }
            Phase::Ended => Some(self),
            _ if self.expired(now_ms) => {
                let until = self.deadline_ms.saturating_add(TOMBSTONE_MS);
                CallEntry { phase: Phase::Ended, deadline_ms: until, end_reason: Some(if self.phase == Phase::Live { HangupReason::Unpaid } else { HangupReason::Timeout }), ..self }.at(now_ms)
            }
            _ => Some(self),
        }
    }

    /// First device delivery anchors only the callee's ring deadline. Age the
    /// row first so late delivery can never revive an expired call.
    pub fn device_fetched(self, now_ms: u64) -> Option<Self> {
        self.at(now_ms).map(|e| match (e.side, e.phase) {
            (Side::Callee, Phase::AwaitingDevice) => Self {
                phase: Phase::Ringing,
                deadline_ms: now_ms.saturating_add(RING_TIMEOUT_MS),
                ..e
            },
            _ => e,
        })
    }

    fn open(&self) -> bool {
        matches!(self.phase, Phase::AwaitingDevice | Phase::Ringing | Phase::Live)
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
            None => Ok(CallEntry { side: Side::Caller, phase: Phase::Reserved, deadline_ms: now_ms.saturating_add(RING_TIMEOUT_MS), pending: Some(pending), paid_until_ms: None, next_block_seq: 0, end_reason: None, unpaid_notice_used: false, free_reply_receipts: Vec::new() }),
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
                _ if !e.open() => Err(CallRefusal::UnknownCall),
                // ICE changes nothing once paid: no reservation needed.
                KIND_ICE_CANDIDATE => Ok(e),
                _ => Ok(CallEntry { pending: Some(pending), ..e }),
            }
        }
        _ => Err(CallRefusal::NotCallKind),
    }
}

/// The reserved signal's payment settled: publish its transition. An unserviceable
/// ended caller block clears its reservation; the outbox journal retains payment evidence
/// and delivery still lets the callee grant service or audit an overpayment.
pub fn commit(entry: CallEntry, operation_id: &str, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    let Some(p) = entry.pending.clone().filter(|p| p.operation_id == operation_id) else {
        return Ok(entry);
    };
    let cleared = CallEntry { pending: None, ..entry };
    Ok(match (p.kind, cleared.phase) {
        // Outlast every answer the callee may send inside its own window,
        // including routing, its device wait, transit and clock skew.
        (KIND_CALL_INVITE, Phase::Reserved) => CallEntry { phase: Phase::Ringing, deadline_ms: now_ms.saturating_add(CALLER_ANSWER_WINDOW_MS), ..cleared },
        (KIND_CALL_ANSWER, Phase::Ringing) => cleared.answered(now_ms),
        (KIND_CALL_BLOCK, _) => {
            // The callee decides whether a paid interval can still be served.
            // Deliver even beyond our local resume window so it can audit an
            // overpayment; the outgoing journal retains the payment evidence.
            let unpaid_end = match (cleared.phase, cleared.end_reason) {
                (Phase::Live, _) => Some(cleared.deadline_ms),
                (Phase::Ended, Some(HangupReason::Unpaid)) => Some(cleared.deadline_ms.saturating_sub(TOMBSTONE_MS)),
                _ => None,
            };
            if let Some(end) = unpaid_end.filter(|end| cleared.side == Side::Caller
                && now_ms > end.saturating_add(CALL_BLOCK_RESUME_MS)) {
                CallEntry { phase: Phase::Ended, end_reason: Some(HangupReason::Unpaid),
                    deadline_ms: end.saturating_add(TOMBSTONE_MS), ..cleared }
            } else {
                match apply_block(cleared.clone(), cleared.next_block_seq, now_ms) {
                    Ok(next) => next,
                    Err(_) if cleared.side == Side::Caller && cleared.phase == Phase::Ended => cleared,
                    Err(e) => return Err(e),
                }
            }
        },
        (KIND_CALL_HANGUP, Phase::Live) if cleared.side == Side::Callee && cleared.unpaid_notice_used => {
            // A notice reserved before a late block must never end the resumed interval.
            CallEntry { unpaid_notice_used: false, ..cleared }
        },
        (KIND_CALL_HANGUP, Phase::AwaitingDevice | Phase::Ringing | Phase::Live | Phase::Reserved) => {
            CallEntry { phase: Phase::Ended, deadline_ms: now_ms.saturating_add(TOMBSTONE_MS), ..cleared }
        }
        _ => cleared,
    })
}

/// Where a saved free reply stands against its call row (see
/// [`free_reply_transition`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreeReplyCheck {
    /// Its exact reservation is current: store this entry, which carries the
    /// transition and the reply's receipt, in one write.
    Apply(CallEntry),
    /// Its receipt is already on the row: the transition happened.
    AlreadyApplied,
    /// Definitely not applied and no longer applicable: no receipt for this
    /// operation, and its reservation is gone, replaced by another
    /// operation's, or the call is not in a phase this reply may move.
    Invalid,
    /// The evidence contradicts itself: an empty digest, an unknown kind, a
    /// receipt for this operation naming another request, peer or call, or a
    /// reservation under this operation's id for another request or kind.
    Corrupt,
    /// The row already holds [`MAX_FREE_REPLY_RECEIPTS`]; nothing is dropped.
    Full,
}

/// Check a saved free reply against the stored (not yet aged) call row and,
/// if its own reservation is current, apply its transition with its receipt.
/// An answer moves only a ringing call to live; a decline only a ringing or
/// device-waiting call to ended. A generic commit that leaves the state
/// unchanged, an ended call, or a missing reservation is never treated as
/// this reply's transition.
pub fn free_reply_transition(entry: Option<CallEntry>, receipt: &FreeReplyReceipt, now_ms: u64) -> FreeReplyCheck {
    if receipt.request_hash.is_empty() || receipt.operation_id.is_empty()
        || !matches!(receipt.kind, KIND_CALL_ANSWER | KIND_CALL_HANGUP)
    {
        return FreeReplyCheck::Corrupt;
    }
    let Some(raw) = entry else { return FreeReplyCheck::Invalid };
    let mut same = raw.free_reply_receipts.iter().filter(|r| r.operation_id == receipt.operation_id);
    match (same.next(), same.next()) {
        (None, _) => {}
        (Some(found), None) if found.binds(receipt) => return FreeReplyCheck::AlreadyApplied,
        _ => return FreeReplyCheck::Corrupt,
    }
    let Some(e) = raw.at(now_ms) else { return FreeReplyCheck::Invalid };
    let exact = Pending { operation_id: receipt.operation_id.clone(), kind: receipt.kind, request_hash: receipt.request_hash.clone() };
    match e.pending.as_ref() {
        Some(p) if *p == exact => {}
        // This operation's id on another request or kind: neither ours nor another's.
        Some(p) if p.operation_id == receipt.operation_id => return FreeReplyCheck::Corrupt,
        _ => return FreeReplyCheck::Invalid,
    }
    if e.side != Side::Callee {
        return FreeReplyCheck::Invalid;
    }
    let (eligible, to) = match receipt.kind {
        KIND_CALL_ANSWER => (e.phase == Phase::Ringing, Phase::Live),
        _ => (matches!(e.phase, Phase::Ringing | Phase::AwaitingDevice), Phase::Ended),
    };
    if !eligible {
        return FreeReplyCheck::Invalid;
    }
    if e.free_reply_receipts.len() >= MAX_FREE_REPLY_RECEIPTS {
        return FreeReplyCheck::Full;
    }
    let Ok(mut next) = commit(e, &receipt.operation_id, now_ms) else { return FreeReplyCheck::Invalid };
    if next.phase != to || next.pending.is_some() {
        return FreeReplyCheck::Invalid;
    }
    next.free_reply_receipts.push(FreeReplyReceipt { phase: to.as_str().into(), applied_ms: now_ms, ..receipt.clone() });
    FreeReplyCheck::Apply(next)
}

/// The reserved signal was definitely not paid: undo the reservation. An
/// offer that never went out is forgotten (`None`); other signals just drop
/// their pending mark.
pub fn release(entry: CallEntry, operation_id: &str) -> Option<CallEntry> {
    match &entry.pending {
        Some(p) if p.operation_id == operation_id && p.kind == KIND_CALL_INVITE && entry.phase == Phase::Reserved => None,
        Some(p) if p.operation_id == operation_id => {
            let release_notice = p.kind == KIND_CALL_HANGUP && entry.unpaid_notice_used
                && (entry.side == Side::Callee
                    || (entry.phase == Phase::Ended && entry.side == Side::Caller
                        && entry.end_reason == Some(HangupReason::DurationCap)));
            Some(CallEntry { pending: None, unpaid_notice_used: entry.unpaid_notice_used && !release_notice, ..entry })
        }
        _ => Some(entry),
    }
}

/// A signal this node received (paid, gate-accepted). Returns the entry to store.
pub fn receive(entry: Option<CallEntry>, kind: u16, reason: Option<HangupReason>, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    match kind {
        KIND_CALL_INVITE => match entry {
            None => Ok(CallEntry { side: Side::Callee, phase: Phase::AwaitingDevice, deadline_ms: now_ms.saturating_add(DEVICE_WAIT_MS), pending: None, paid_until_ms: None, next_block_seq: 0, end_reason: None, unpaid_notice_used: false, free_reply_receipts: Vec::new() }),
            Some(_) => Err(CallRefusal::Replayed),
        },
        KIND_CALL_ANSWER => {
            let e = entry.ok_or(CallRefusal::UnknownCall)?;
            match (e.phase, e.side) {
                // A reserved offer was never paid: nobody can answer it.
                (Phase::Reserved | Phase::AwaitingDevice | Phase::Ended, _) => Err(CallRefusal::UnknownCall),
                (Phase::Ringing, Side::Caller) => Ok(e.answered(now_ms)),
                (Phase::Ringing, Side::Callee) => Err(CallRefusal::WrongSide),
                (Phase::Live, _) => Err(CallRefusal::NotRinging),
            }
        }
        KIND_ICE_CANDIDATE => entry.filter(|e| e.open()).ok_or(CallRefusal::UnknownCall),
        KIND_CALL_HANGUP => {
            let e = entry.ok_or(CallRefusal::UnknownCall)?;
            if reason == Some(HangupReason::Unpaid) && e.side != Side::Caller {
                return Err(CallRefusal::UnknownCall);
            }
            if e.phase == Phase::Ended {
                if e.side == Side::Caller && e.end_reason == Some(HangupReason::Unpaid)
                    && matches!(reason, Some(HangupReason::Hangup | HangupReason::Declined)) {
                    // Explicit termination also wins after local expiry. Preserve
                    // replay protection, but never resume on a later settlement.
                    return Ok(CallEntry { pending: None, end_reason: reason, ..e });
                }
                if e.end_reason != Some(HangupReason::Unpaid)
                    || reason != Some(HangupReason::Unpaid)
                    || e.unpaid_notice_used
                {
                    return Err(CallRefusal::UnknownCall);
                }
                // Preserve the tombstone and pending evidence; consume only the notice.
                return Ok(CallEntry { unpaid_notice_used: true, ..e });
            }
            if !e.open() { return Err(CallRefusal::UnknownCall); }
            if reason == Some(HangupReason::Unpaid) && e.media_admitted(now_ms) {
                // A delayed notice for an older interval cannot revoke settled service.
                return Err(CallRefusal::UnknownCall);
            }
            // Explicit hangup wins. Reconciliation and callee overpayment auditing
            // use the outbox journal, so an unserviceable call need not hold a slot.
            let pending = if reason == Some(HangupReason::Unpaid) { e.pending.clone() } else { None };
            Ok(CallEntry { phase: Phase::Ended, pending, deadline_ms: now_ms.saturating_add(TOMBSTONE_MS), end_reason: reason, unpaid_notice_used: reason == Some(HangupReason::Unpaid), ..e })
        }
        _ => Err(CallRefusal::NotCallKind),
    }
}

/// Check one sequential block without granting media or moving money.
fn check_block(entry: &CallEntry, seq: u32, now_ms: u64) -> Result<(), CallRefusal> {
    if entry.phase != Phase::Live || entry.expired(now_ms) {
        return Err(CallRefusal::UnknownCall);
    }
    if seq != entry.next_block_seq || u64::from(seq) >= MAX_CALL_MS / CALL_BLOCK_MS {
        return Err(CallRefusal::Sequence);
    }
    if entry.next_block_due_ms().is_none_or(|due| now_ms < due) {
        return Err(CallRefusal::NotDue);
    }
    Ok(())
}

fn apply_block(entry: CallEntry, seq: u32, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    if seq != entry.next_block_seq || u64::from(seq) >= MAX_CALL_MS / CALL_BLOCK_MS {
        return Err(CallRefusal::Sequence);
    }
    if entry.side == Side::Callee && entry.paid_until_ms == Some(0) {
        return Err(CallRefusal::UnknownCall);
    }
    let end = match (entry.phase, entry.end_reason) {
        (Phase::Live, _) => entry.deadline_ms,
        (Phase::Ended, Some(HangupReason::Unpaid)) => entry.deadline_ms.saturating_sub(TOMBSTONE_MS),
        _ => return Err(CallRefusal::UnknownCall),
    };
    let late = now_ms > end;
    if late && now_ms > end.saturating_add(CALL_BLOCK_RESUME_MS) {
        return Err(CallRefusal::UnknownCall);
    }
    if !late { check_block(&entry, seq, now_ms)?; }
    let start = if late { now_ms } else {
        entry.paid_until_ms.unwrap_or_else(|| entry.deadline_ms.saturating_sub(CALL_BLOCK_INITIAL_MS))
    };
    let until = start.saturating_add(CALL_BLOCK_MS);
    // Keep a pending Unpaid notice identifiable until its commit/release.
    let notice_pending = entry.side == Side::Callee && entry.unpaid_notice_used
        && entry.pending.as_ref().is_some_and(|p| p.kind == KIND_CALL_HANGUP);
    Ok(CallEntry { phase: Phase::Live, end_reason: None, unpaid_notice_used: notice_pending,
        paid_until_ms: Some(until), next_block_seq: seq.saturating_add(1),
        deadline_ms: until.saturating_add(CALL_BLOCK_GRACE_MS), ..entry })
}

/// Gate-accepted block, strictly caller → callee. Honour late settlement within
/// the bounded Unpaid resume window; refusal requires overpayment accounting.
pub fn receive_block(entry: Option<CallEntry>, seq: u32, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    let entry = entry.ok_or(CallRefusal::UnknownCall)?;
    if entry.side != Side::Callee { return Err(CallRefusal::WrongSide); }
    apply_block(entry, seq, now_ms)
}

/// The callee's pre-invoice check never resumes a call or moves money.
pub fn validate_block_invoice(entry: &CallEntry, seq: u32, now_ms: u64) -> Result<(), CallRefusal> {
    if entry.side != Side::Callee { return Err(CallRefusal::WrongSide); }
    check_block(entry, seq, now_ms)?;
    if now_ms.saturating_add(CALL_BLOCK_INVOICE_MARGIN_MS) > entry.deadline_ms {
        return Err(CallRefusal::Invalid("call block invoice too close to deadline"));
    }
    Ok(())
}

/// Recheck before a new outgoing charge, including a reconciled failed retry.
pub fn validate_outgoing_block(entry: &CallEntry, seq: u32, now_ms: u64) -> Result<(), CallRefusal> {
    if entry.side != Side::Caller { return Err(CallRefusal::WrongSide); }
    check_block(entry, seq, now_ms)
}

/// Reserve a caller's block before payment. The request hash binds its seq;
/// no incoming block is accepted on the caller side while it is pending.
pub fn reserve_block(entry: Option<CallEntry>, seq: u32, operation_id: &str, request_hash: &str, now_ms: u64) -> Result<CallEntry, CallRefusal> {
    let entry = entry.ok_or(CallRefusal::UnknownCall)?;
    if entry.side != Side::Caller { return Err(CallRefusal::WrongSide); }
    if let Some(pending) = &entry.pending {
        return if pending.kind == KIND_CALL_BLOCK && pending.is(operation_id, request_hash) { Ok(entry) } else { Err(CallRefusal::InFlight) };
    }
    check_block(&entry, seq, now_ms)?;
    Ok(CallEntry { pending: Some(Pending { operation_id: operation_id.into(), kind: KIND_CALL_BLOCK, request_hash: request_hash.into() }), ..entry })
}

/// A timer may notify an already ended unpaid call through normal compose.
/// This never reopens the call or grants media. Existing pending evidence wins.
pub fn reserve_unpaid_hangup(entry: Option<CallEntry>, operation_id: &str, request_hash: &str) -> Result<CallEntry, CallRefusal> {
    reserve_end_notice(entry, Side::Callee, HangupReason::Unpaid, operation_id, request_hash)
}

/// A caller notifies its peer after ending at the owner's paid-duration cap.
pub fn reserve_duration_hangup(entry: Option<CallEntry>, operation_id: &str, request_hash: &str) -> Result<CallEntry, CallRefusal> {
    reserve_end_notice(entry, Side::Caller, HangupReason::DurationCap, operation_id, request_hash)
}

fn reserve_end_notice(entry: Option<CallEntry>, side: Side, reason: HangupReason, operation_id: &str, request_hash: &str) -> Result<CallEntry, CallRefusal> {
    let entry = entry.ok_or(CallRefusal::UnknownCall)?;
    if entry.side != side || entry.phase != Phase::Ended || entry.end_reason != Some(reason) {
        return Err(CallRefusal::UnknownCall);
    }
    if let Some(pending) = &entry.pending {
        return if pending.kind == KIND_CALL_HANGUP && pending.is(operation_id, request_hash) { Ok(entry) } else { Err(CallRefusal::InFlight) };
    }
    if entry.unpaid_notice_used { return Err(CallRefusal::UnknownCall); }
    Ok(CallEntry { unpaid_notice_used: true, pending: Some(Pending { operation_id: operation_id.into(), kind: KIND_CALL_HANGUP, request_hash: request_hash.into() }), ..entry })
}

/// Stored call rows as of one instant, split by what they hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallCounts {
    /// Open calls with this peer (reserved, ringing, live, or pending).
    pub open_peer: u64,
    pub open_total: u64,
    /// Burned ids with this peer (ended, replay protection not yet over).
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
    fn an_unfetched_invite_ends_after_fifteen_seconds_without_ringing() {
        let entry = receive(None, 400, None, 1_000).unwrap();
        assert_eq!(entry.phase.as_str(), "awaiting_device");
        assert_eq!(entry.deadline_ms, 16_000);
        assert_eq!(entry.clone().at(15_999).unwrap().phase.as_str(), "awaiting_device");
        assert_eq!(entry.at(16_000).unwrap().phase, Phase::Ended);
    }

    #[test]
    fn first_device_gets_sixty_seconds_and_second_device_does_not_reset_it() {
        let entry = receive(None, 400, None, 1_000).unwrap().device_fetched(11_000).unwrap();
        assert_eq!((entry.phase, entry.deadline_ms), (Phase::Ringing, 71_000));
        assert_eq!(entry.clone().device_fetched(15_000), Some(entry.clone()));
        assert_eq!(entry.clone().at(70_999).unwrap().phase, Phase::Ringing);
        assert_eq!(entry.at(71_000).unwrap().phase, Phase::Ended);
    }

    #[test]
    fn late_device_fetch_never_revives_an_awaiting_row() {
        for now in [16_000, 16_001, 16_000 + TOMBSTONE_MS + 1] {
            let entry = receive(None, 400, None, 1_000).unwrap().device_fetched(now);
            assert!(entry.is_none_or(|e| e.phase == Phase::Ended));
        }
    }

    #[test]
    fn awaiting_device_accepts_paid_ice_and_hangup() {
        let entry = receive(None, 400, None, 1_000).unwrap();
        assert_eq!(receive(Some(entry.clone()), 402, None, 2_000).unwrap(), entry);
        assert_eq!(receive(Some(entry.clone()), 403, Some(HangupReason::Hangup), 2_000).unwrap().phase, Phase::Ended);
        assert!(reserve(Some(entry.clone()), 402, "ice", "h", 2_000).is_ok());
        let pending = reserve(Some(entry), 403, "hangup", "h", 2_000).unwrap();
        assert_eq!(commit(pending, "hangup", 2_001).unwrap().phase, Phase::Ended);
    }

    #[test]
    fn caller_deadline_starts_at_payment_and_outlasts_the_device_wait() {
        let entry = commit(reserve(None, 400, "offer", "h", 1_000).unwrap(), "offer", 2_000).unwrap();
        assert_eq!((entry.phase, entry.deadline_ms), (Phase::Ringing, 2_000 + CALLER_ANSWER_WINDOW_MS));
        assert_eq!(entry.clone().device_fetched(11_000), Some(entry.clone()));
    }

    /// Two nodes, worst case: the offer is stamped before payment, arrives as
    /// late as the callee accepts on a callee clock running behind by the full
    /// skew, a device takes it at the end of the wait, and the callee answers
    /// at the end of its ring window. The answer, after transit, still finds
    /// the caller ringing; one the callee could not send in time is refused.
    #[test]
    fn caller_window_covers_every_answer_inside_the_callee_window() {
        let offer_ms = 1_000;
        let paid_ms = offer_ms; // the offer is stamped no later than payment
        let caller = commit(reserve(None, 400, "offer", "h", offer_ms).unwrap(), "offer", paid_ms).unwrap();
        // Real time = caller clock; the callee's clock is behind by the skew.
        let skew = CALL_CLOCK_SKEW_MS;
        let arrived_local = offer_ms + INVITE_MAX_AGE_MS;
        assert!(invite_fresh(offer_ms, arrived_local));
        assert!(!invite_fresh(offer_ms, arrived_local + 1), "an older offer is refused");
        assert!(!invite_fresh(arrived_local + skew + 1, arrived_local), "a future offer beyond the skew is refused");
        let callee = receive(None, 400, None, arrived_local).unwrap();
        // A stream write armed at the last moment of the wait completes as
        // late as the write timeout allows and rings from its completion.
        let written_local = callee.deadline_ms - 1 + DEVICE_WRITE_TIMEOUT_MS;
        let ringing = CallEntry { deadline_ms: written_local + RING_TIMEOUT_MS, ..callee.clone().device_fetched(callee.deadline_ms - 1).unwrap() };
        let answered_local = ringing.deadline_ms - 1;
        assert_eq!(ringing.clone().at(answered_local).unwrap().phase, Phase::Ringing, "callee may still answer");
        let answer_reaches_caller = answered_local + skew + ANSWER_TRANSIT_MS;
        let live = receive(Some(caller.clone().at(answer_reaches_caller).unwrap()), 401, None, answer_reaches_caller).unwrap();
        assert_eq!(live.phase, Phase::Live);
        // Tight, not unbounded: only the two "last moment" milliseconds spare.
        assert_eq!(caller.deadline_ms - answer_reaches_caller, 2);
    }

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
        assert_eq!(CallSignal::parse(405, "{}"), Err(CallRefusal::NotCallKind));
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
        // Review P1: an answer cannot be accepted for an offer that was never paid.
        assert_eq!(receive(Some(r.clone()), 401, None, 1), Err(CallRefusal::UnknownCall));
        // Definite nonpayment: forgotten, so the same id can be offered again.
        assert_eq!(release(r.clone(), "op1"), None);
        // Paid: now it rings and accepts the callee's answer once.
        let ringing = commit(r, "op1", 5).unwrap();
        assert_eq!((ringing.phase, ringing.pending.clone()), (Phase::Ringing, None));
        let live = receive(Some(ringing.clone()), 401, None, 6).unwrap();
        assert_eq!(live.phase, Phase::Live);
        assert_eq!(receive(Some(live), 401, None, 7), Err(CallRefusal::NotRinging));
        // Repeating an already committed offer is idempotent.
        assert_eq!(commit(ringing.clone(), "op1", 9).unwrap(), ringing);
    }

    #[test]
    fn our_answer_and_hangup_change_state_only_when_paid() {
        let ringing = receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
        assert_eq!(reserve(Some(ringing.clone()), 401, "a", "h", 1).unwrap().phase, Phase::Ringing, "reserved, not yet live");
        let pending = reserve(Some(ringing.clone()), 401, "a", "h", 1).unwrap();
        // A second signal while the answer is being paid waits.
        assert_eq!(reserve(Some(pending.clone()), 403, "h", "h", 1), Err(CallRefusal::InFlight));
        // Review P1: an unpaid answer leaves the call ringing, so it can be retried.
        let back = release(pending.clone(), "a").unwrap();
        assert_eq!(back, ringing);
        assert!(reserve(Some(back), 401, "a2", "h", 2).is_ok());
        let live = commit(pending, "a", 3).unwrap();
        assert_eq!(live.phase, Phase::Live);
        let hang = reserve(Some(live.clone()), 403, "h", "h", 4).unwrap();
        assert_eq!(hang.phase, Phase::Live);
        assert_eq!(release(hang.clone(), "h").unwrap(), live);
        let ended = commit(hang, "h", 5).unwrap();
        assert_eq!((ended.phase, ended.deadline_ms), (Phase::Ended, 5 + TOMBSTONE_MS));
        // The caller cannot answer its own call.
        let own = commit(reserve(None, 400, "o", "h", 0).unwrap(), "o", 0).unwrap();
        assert_eq!(reserve(Some(own), 401, "x", "h", 1), Err(CallRefusal::WrongSide));
    }

    #[test]
    fn signals_need_an_open_call_and_ids_stay_burned_until_their_deadline() {
        for k in [401, 402, 403] {
            assert_eq!(receive(None, k, None, 0), Err(CallRefusal::UnknownCall));
            assert_eq!(reserve(None, k, "op", "h", 0), Err(CallRefusal::UnknownCall));
        }
        let ringing = receive(None, 400, None, 0).unwrap();
        assert_eq!(receive(Some(ringing.clone()), 400, None, 1), Err(CallRefusal::Replayed));
        let ended = receive(Some(ringing), 403, None, 2).unwrap();
        assert_eq!(receive(Some(ended.clone()), 402, None, 3), Err(CallRefusal::UnknownCall));
        // Burned until the tombstone runs out, then free again.
        assert!(ended.clone().at(2 + TOMBSTONE_MS - 1).is_some());
        assert!(ended.at(2 + TOMBSTONE_MS).is_none());
        // Unanswered: stops ringing at the deadline, id stays burned a day after.
        let r = receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
        let late = r.at(RING_TIMEOUT_MS).unwrap();
        assert_eq!((late.phase, late.deadline_ms), (Phase::Ended, RING_TIMEOUT_MS + TOMBSTONE_MS));
        assert_eq!(receive(Some(late.clone()), 401, None, RING_TIMEOUT_MS), Err(CallRefusal::UnknownCall));
        assert_eq!(late.replay_until_ms(), RING_TIMEOUT_MS + TOMBSTONE_MS);
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
        // Burned ids never count against open calls (review N3).
        assert!(has_room(&c(MAX_OPEN_CALLS_PER_PEER - 1, MAX_OPEN_CALLS - 1, u64::MAX, u64::MAX)).is_ok());
        assert_eq!(burned_excess(MAX_BURNED_PER_PEER - 1, MAX_BURNED_PER_PEER), 0);
        assert_eq!(burned_excess(MAX_BURNED_PER_PEER, MAX_BURNED_PER_PEER), 1);
        // An id ended at t is evictable only from t + BURN_MIN_MS.
        let ended = commit(reserve(Some(receive(None, 400, None, 0).unwrap()), 403, "h", "h", 0).unwrap(), "h", 0).unwrap();
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

    fn free_receipt(kind: u16, op: &str, hash: &str) -> FreeReplyReceipt {
        FreeReplyReceipt { peer: "ab".into(), call_id: ID.into(), kind, operation_id: op.into(), request_hash: hash.into(), phase: String::new(), applied_ms: 0 }
    }

    /// A callee row ringing (or still waiting for a device) with this reply reserved.
    fn reserved_reply(kind: u16, op: &str, hash: &str, fetched: bool) -> CallEntry {
        let mut entry = receive(None, 400, None, 0).unwrap();
        if fetched { entry = entry.device_fetched(0).unwrap(); }
        reserve(Some(entry), kind, op, hash, 0).unwrap()
    }

    #[test]
    fn a_free_reply_moves_only_its_own_reserved_call_and_records_its_receipt() {
        for (kind, fetched, to) in [(401u16, true, Phase::Live), (403, true, Phase::Ended), (403, false, Phase::Ended)] {
            let receipt = free_receipt(kind, "op", "hash");
            let FreeReplyCheck::Apply(next) = free_reply_transition(Some(reserved_reply(kind, "op", "hash", fetched)), &receipt, 5) else {
                panic!("{kind}/{fetched}: the exact reservation must apply");
            };
            assert_eq!((next.phase, next.pending.clone()), (to, None), "{kind}/{fetched}");
            assert_eq!(next.free_reply_receipts.len(), 1);
            assert!(next.free_reply_receipts[0].binds(&receipt));
            assert_eq!((next.free_reply_receipts[0].phase.as_str(), next.free_reply_receipts[0].applied_ms), (to.as_str(), 5));
            // Applying again finds the receipt: the transition is not repeated.
            assert_eq!(free_reply_transition(Some(next.clone()), &receipt, 6), FreeReplyCheck::AlreadyApplied);
            // A later end keeps the historical receipt.
            let later = CallEntry { phase: Phase::Ended, deadline_ms: 7 + TOMBSTONE_MS, end_reason: Some(HangupReason::Hangup), ..next };
            assert_eq!(free_reply_transition(Some(later), &receipt, 8), FreeReplyCheck::AlreadyApplied);
        }
    }

    #[test]
    fn a_free_reply_without_its_receipt_or_reservation_is_invalid() {
        let receipt = free_receipt(401, "op", "hash");
        // No call, a call ended another way, another request's reservation.
        assert_eq!(free_reply_transition(None, &receipt, 1), FreeReplyCheck::Invalid);
        let ringing = receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
        let hung_up = receive(Some(reserved_reply(401, "op", "hash", true)), 403, Some(HangupReason::Hangup), 1).unwrap();
        assert_eq!(free_reply_transition(Some(hung_up), &receipt, 2), FreeReplyCheck::Invalid);
        assert_eq!(free_reply_transition(Some(ringing.clone()), &receipt, 1), FreeReplyCheck::Invalid);
        for kind in [401u16, 403] {
            let entry = reserve(Some(ringing.clone()), kind, "other", "hash", 0).unwrap();
            assert_eq!(free_reply_transition(Some(entry), &receipt, 1), FreeReplyCheck::Invalid, "{kind}");
        }
        // The ring window closed while the reply was reserved.
        assert_eq!(free_reply_transition(Some(reserved_reply(401, "op", "hash", true)), &receipt, RING_TIMEOUT_MS), FreeReplyCheck::Invalid);
        // An answer cannot move a call still waiting for a device.
        let waiting = CallEntry { pending: Some(Pending { operation_id: "op".into(), kind: 401, request_hash: "hash".into() }), ..receive(None, 400, None, 0).unwrap() };
        assert_eq!(free_reply_transition(Some(waiting), &receipt, 1), FreeReplyCheck::Invalid);
        // A caller row is never a free reply's call.
        let caller = CallEntry { side: Side::Caller, ..reserved_reply(401, "op", "hash", true) };
        assert_eq!(free_reply_transition(Some(caller), &receipt, 1), FreeReplyCheck::Invalid);
    }

    #[test]
    fn a_hangup_that_only_clears_an_unpaid_notice_is_not_a_decline() {
        let live = CallEntry { phase: Phase::Live, unpaid_notice_used: true, deadline_ms: 100,
            pending: Some(Pending { operation_id: "op".into(), kind: 403, request_hash: "hash".into() }),
            ..receive(None, 400, None, 0).unwrap() };
        assert_eq!(free_reply_transition(Some(live), &free_receipt(403, "op", "hash"), 1), FreeReplyCheck::Invalid);
    }

    #[test]
    fn contradictory_free_reply_evidence_is_corrupt_not_applied() {
        let entry = reserved_reply(401, "op", "hash", true);
        assert_eq!(free_reply_transition(Some(entry.clone()), &free_receipt(401, "op", ""), 1), FreeReplyCheck::Corrupt);
        // This operation's id reserved for another request or kind, or without
        // a digest (a legacy reservation is not this request's proof).
        let ringing = receive(None, 400, None, 0).unwrap().device_fetched(0).unwrap();
        for (kind, hash) in [(401u16, "other"), (403, "hash"), (401, "")] {
            let other = CallEntry { pending: Some(Pending { operation_id: "op".into(), kind, request_hash: hash.into() }), ..ringing.clone() };
            assert_eq!(free_reply_transition(Some(other), &free_receipt(401, "op", "hash"), 1), FreeReplyCheck::Corrupt, "{kind}/{hash}");
        }
        assert_eq!(free_reply_transition(Some(entry.clone()), &free_receipt(400, "op", "hash"), 1), FreeReplyCheck::Corrupt);
        let FreeReplyCheck::Apply(applied) = free_reply_transition(Some(entry), &free_receipt(401, "op", "hash"), 1) else { panic!() };
        // A receipt for this operation that names another request, call or peer.
        for other in [free_receipt(401, "op", "other"), FreeReplyReceipt { call_id: "x".into(), ..free_receipt(401, "op", "hash") },
            FreeReplyReceipt { peer: "cd".into(), ..free_receipt(401, "op", "hash") }] {
            assert_eq!(free_reply_transition(Some(applied.clone()), &other, 2), FreeReplyCheck::Corrupt);
        }
        // Two receipts for one operation.
        let doubled = CallEntry { free_reply_receipts: vec![applied.free_reply_receipts[0].clone(); 2], ..applied };
        assert_eq!(free_reply_transition(Some(doubled), &free_receipt(401, "op", "hash"), 2), FreeReplyCheck::Corrupt);
    }

    #[test]
    fn the_receipt_bound_refuses_a_transition_and_never_drops_a_receipt() {
        let held: Vec<_> = (0..MAX_FREE_REPLY_RECEIPTS).map(|i| free_receipt(403, &format!("held{i}"), "hash")).collect();
        let full = CallEntry { free_reply_receipts: held.clone(), ..reserved_reply(401, "op", "hash", true) };
        assert_eq!(free_reply_transition(Some(full.clone()), &free_receipt(401, "op", "hash"), 1), FreeReplyCheck::Full);
        assert_eq!(full.free_reply_receipts, held);
        for receipt in &held {
            assert_eq!(free_reply_transition(Some(full.clone()), receipt, 1), FreeReplyCheck::AlreadyApplied);
        }
    }

    #[test]
    fn a_row_holding_a_receipt_is_never_aged_out() {
        let FreeReplyCheck::Apply(declined) = free_reply_transition(Some(reserved_reply(403, "op", "hash", true)), &free_receipt(403, "op", "hash"), 0) else { panic!() };
        let after = declined.replay_until_ms() + TOMBSTONE_MS;
        let kept = declined.clone().at(after).expect("the receipt keeps its row");
        assert_eq!((kept.phase, kept.free_reply_receipts.len()), (Phase::Ended, 1));
        // The id stays burned while the row is kept.
        assert_eq!(receive(Some(kept), 400, None, after), Err(CallRefusal::Replayed));
        assert!(CallEntry { free_reply_receipts: Vec::new(), ..declined }.at(after).is_none());
    }

}


#[cfg(test)]
mod hangup_invoice_tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn live(side: Side) -> CallEntry {
        let caller = commit(reserve(None, 400, "offer", "hash", 0).unwrap(), "offer", 0).unwrap();
        CallEntry { side, phase: Phase::Live, deadline_ms: 90_000, ..caller }
    }

    #[test]
    fn hangup_purpose_round_trips_and_rejects_malformed() {
        for side in [Side::Caller, Side::Callee] {
            assert_eq!(parse_hangup_invoice_purpose(&hangup_invoice_purpose(ID, side)), Some((ID.into(), side)));
        }
        for bad in [
            "konsensus:call_hangup:", "konsensus:call_hangup:0123:caller",
            &format!("konsensus:call_hangup:{ID}"), &format!("konsensus:call_hangup:{ID}:both"),
            &format!("konsensus:call_block:{ID}:0"), &format!("konsensus:call_hangup:{}:caller", ID.to_uppercase()),
        ] {
            assert_eq!(parse_hangup_invoice_purpose(bad), None, "{bad}");
        }
        assert!(HANGUP_INVOICE_SEQ as u64 >= MAX_CALL_MS / CALL_BLOCK_MS, "a hangup binding must never be a block sequence");
    }

    #[test]
    fn only_an_ordinary_hangup_of_a_live_call_uses_the_invoice() {
        let entry = live(Side::Caller);
        for reason in [None, Some(HangupReason::Hangup), Some(HangupReason::Failed), Some(HangupReason::Busy)] {
            assert!(hangup_uses_invoice(Some(&entry), reason), "{reason:?}");
        }
        for reason in [Some(HangupReason::Unpaid), Some(HangupReason::DurationCap)] {
            assert!(!hangup_uses_invoice(Some(&entry), reason), "{reason:?}");
        }
        for phase in [Phase::Reserved, Phase::AwaitingDevice, Phase::Ringing, Phase::Ended] {
            assert!(!hangup_uses_invoice(Some(&CallEntry { phase, ..entry.clone() }), None), "{phase:?}");
        }
        assert!(!hangup_uses_invoice(None, None));
    }

    #[test]
    fn a_hangup_invoice_is_issued_only_for_a_live_call_from_the_other_side() {
        let callee = live(Side::Callee);
        assert_eq!(validate_hangup_invoice(Some(&callee), Side::Caller), Ok(()));
        assert_eq!(validate_hangup_invoice(Some(&live(Side::Caller)), Side::Callee), Ok(()));
        assert_eq!(validate_hangup_invoice(Some(&callee), Side::Callee), Err(CallRefusal::WrongSide));
        let ended = CallEntry { phase: Phase::Ended, end_reason: Some(HangupReason::Hangup), ..callee.clone() };
        assert_eq!(validate_hangup_invoice(Some(&ended), Side::Caller), Err(CallRefusal::UnknownCall));
        assert_eq!(validate_hangup_invoice(Some(&CallEntry { phase: Phase::Ringing, ..callee }), Side::Caller), Err(CallRefusal::UnknownCall));
        assert_eq!(validate_hangup_invoice(None, Side::Caller), Err(CallRefusal::UnknownCall));
    }
}

#[cfg(test)]
mod duration_cap_tests {
    use super::*;

    #[test]
    fn duration_notice_is_single_use_and_preserves_the_terminal_boundary() {
        let signal = CallSignal::parse(403, r#"{"v":1,"call_id":"0123456789abcdef0123456789abcdef","reason":"duration_cap"}"#).unwrap();
        assert_eq!(signal.reason, Some(HangupReason::DurationCap));
        let caller = commit(reserve(None, 400, "offer", "hash", 0).unwrap(), "offer", 0).unwrap();
        let ended = CallEntry { phase: Phase::Ended, end_reason: signal.reason,
            deadline_ms: 60_000 + TOMBSTONE_MS, ..caller };
        assert!(reserve_duration_hangup(Some(CallEntry { side: Side::Callee, ..ended.clone() }), "notice", "hash").is_err());
        let pending = reserve_duration_hangup(Some(ended.clone()), "notice", "hash").unwrap();
        assert_eq!(release(pending.clone(), "notice").unwrap(), ended);
        let sent = commit(pending, "notice", 65_000).unwrap();
        assert_eq!(sent.deadline_ms, ended.deadline_ms);
        assert_eq!(sent.end_reason, ended.end_reason);
        assert!(!sent.media_admitted(65_000));
        assert!(reserve_duration_hangup(Some(sent), "again", "hash").is_err());
    }
}
