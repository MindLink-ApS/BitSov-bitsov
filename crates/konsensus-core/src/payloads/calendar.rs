//! Calendar wire payloads — inside the UKM envelope ciphertext for kinds 100-101 and 104.
//!
//! These structs are serialized to JSON, E2EE encrypted via Double Ratchet,
//! and placed in the `ciphertext` field of UKM envelopes.

//!
//! ## Inbound caps
//! A peer's calendar payload is bounded before this node copies, stores or
//! expands any of it. [`CalendarEventPayload::decode`] and
//! [`RsvpPayload::decode`] check the aggregate byte cap first, then decode with
//! pre-copy field bounds (string lengths and list counts are checked on the raw
//! JSON token before serde allocates), then validate the recurrence rule's
//! implied size. Every refusal is a typed [`CalendarPayloadError`] with a
//! stable code the sender can read.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::wire_json;
use crate::wire_json::strings::check_string_bytes;

// ── Inbound caps ────────────────────────────────────────────────────────────
//
// Conservative by design: large enough for every payload this node's own API
// produces, small enough that a hostile peer cannot make the recipient do
// unbounded work. The aggregate byte cap bounds everything serde can allocate
// even before the per-field caps apply.

/// Maximum serialized bytes of one `CalendarEventPayload` (invite or update).
/// An event with the maximum attendees, description and location is ~16 KiB;
/// 64 KiB leaves headroom for escaped UTF-8 while staying far below the 6 MiB
/// envelope ciphertext cap.
pub const MAX_CALENDAR_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum serialized bytes of one `RsvpPayload`.
pub const MAX_RSVP_PAYLOAD_BYTES: usize = 4 * 1024;
/// Calendar events per payload. The wire carries exactly one event per
/// envelope; a top-level array or batch is refused as malformed.
pub const MAX_EVENTS_PER_PAYLOAD: usize = 1;
/// Maximum attendees per event. Matches the owner API's create-event cap.
pub const MAX_ATTENDEES: usize = 100;
/// Maximum bytes of `event_id` (UUIDs are 36).
pub const MAX_EVENT_ID_BYTES: usize = 128;
/// Maximum bytes of `title`.
pub const MAX_TITLE_BYTES: usize = 512;
/// Maximum bytes of `description`.
pub const MAX_DESCRIPTION_BYTES: usize = 8 * 1024;
/// Maximum bytes of `location`.
pub const MAX_LOCATION_BYTES: usize = 1024;
/// Maximum bytes of `tz` (the longest IANA zone name is under 40 bytes).
pub const MAX_TZ_BYTES: usize = 64;
/// Maximum bytes of a node id in `organizer` or `attendees` (64 lowercase hex).
pub const MAX_NODE_ID_HEX_BYTES: usize = 64;
/// Maximum bytes of `color` (`#rrggbbaa` is 9).
pub const MAX_COLOR_BYTES: usize = 32;
/// Maximum bytes of `freq` (the longest token, `MONTHLY`, is 7).
pub const MAX_FREQ_BYTES: usize = 16;
/// Maximum bytes of one `byday` code (RFC 5545 codes are 2).
pub const MAX_BYDAY_CODE_BYTES: usize = 8;
/// Maximum bytes of an RSVP `comment`.
pub const MAX_RSVP_COMMENT_BYTES: usize = 2 * 1024;
/// Maximum occurrences a recurrence rule may imply, by `COUNT` or by
/// `UNTIL` and `BYDAY` together. Equals the expander's 5000-step safety stop,
/// so an admitted bounded series is never truncated when it is viewed. A rule
/// with neither `COUNT` nor `UNTIL` is open-ended; its expansion is bounded by
/// the reader's time window and occurrence budget instead.
pub const MAX_RECURRENCE_INSTANCES: u64 = 5_000;

/// Why an inbound calendar payload was refused. Carries no peer-controlled
/// text: every field is a static name or a number, so it is safe to log and to
/// echo back to the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CalendarPayloadError {
    /// The serialized payload exceeds the aggregate byte cap.
    #[error("calendar payload is {actual} bytes; the cap is {max}")]
    TooLarge { actual: usize, max: usize },
    /// A string field exceeds its byte cap.
    #[error("calendar field `{field}` exceeds {max} bytes")]
    FieldTooLong { field: &'static str, max: usize },
    /// A list field exceeds its entry cap.
    #[error("calendar list `{field}` exceeds {max} entries")]
    TooManyEntries { field: &'static str, max: usize },
    /// The recurrence rule would expand to more instances than the cap.
    #[error("calendar recurrence would expand to {estimated} instances; the cap is {max}")]
    RecurrenceTooLarge { estimated: u64, max: u64 },
    /// The recurrence rule is malformed (`interval` 0 or an unknown `freq`).
    #[error("calendar recurrence is invalid: {0}")]
    RecurrenceInvalid(&'static str),
    /// Not a valid wire JSON document of the expected shape.
    #[error("calendar payload is not valid wire JSON")]
    Malformed,
}

impl CalendarPayloadError {
    /// Every refusal code, for the sender's terminal-rejection classifier: a
    /// `MessageReject` whose reason starts with one of these followed by `:`
    /// consumed the payment proof and must never be retried.
    pub const CODES: [&'static str; 6] = [
        "calendar_too_large",
        "calendar_field_too_long",
        "calendar_too_many_entries",
        "calendar_recurrence_too_large",
        "calendar_recurrence_invalid",
        "calendar_malformed",
    ];

    /// Stable refusal code, sent to the peer as the `MessageReject` reason prefix.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "calendar_too_large",
            Self::FieldTooLong { .. } => "calendar_field_too_long",
            Self::TooManyEntries { .. } => "calendar_too_many_entries",
            Self::RecurrenceTooLarge { .. } => "calendar_recurrence_too_large",
            Self::RecurrenceInvalid(_) => "calendar_recurrence_invalid",
            Self::Malformed => "calendar_malformed",
        }
    }

    /// Whether the refusal is a size or count cap (as opposed to a malformed
    /// document): the sender can shrink the payload and retry.
    pub fn is_cap(&self) -> bool {
        !matches!(self, Self::Malformed | Self::RecurrenceInvalid(_))
    }
}

// Pre-copy cap markers. serde_json prefixes its own position suffix after the
// custom message, so `decode` classifies by prefix. No peer text is included.
const CAP_FIELD_MARKER: &str = "calendar cap field:";
const CAP_LIST_MARKER: &str = "calendar cap list:";

fn field_cap_error<E: de::Error>(field: &'static str) -> E {
    E::custom(format!("{CAP_FIELD_MARKER}{field}"))
}

fn list_cap_error<E: de::Error>(field: &'static str) -> E {
    E::custom(format!("{CAP_LIST_MARKER}{field}"))
}

/// Byte cap of each string field, by wire name. Shared by the pre-copy
/// deserializers, the post-decode validation and the error classifier.
const STRING_FIELD_CAPS: &[(&str, usize)] = &[
    ("event_id", MAX_EVENT_ID_BYTES),
    ("title", MAX_TITLE_BYTES),
    ("description", MAX_DESCRIPTION_BYTES),
    ("tz", MAX_TZ_BYTES),
    ("location", MAX_LOCATION_BYTES),
    ("organizer", MAX_NODE_ID_HEX_BYTES),
    ("attendees", MAX_NODE_ID_HEX_BYTES),
    ("color", MAX_COLOR_BYTES),
    ("freq", MAX_FREQ_BYTES),
    ("byday", MAX_BYDAY_CODE_BYTES),
    ("comment", MAX_RSVP_COMMENT_BYTES),
];

/// Entry cap of each list field, by wire name.
const LIST_FIELD_CAPS: &[(&str, usize)] = &[("attendees", MAX_ATTENDEES), ("byday", MAX_BYDAY)];

fn string_cap(field: &str) -> usize {
    STRING_FIELD_CAPS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, max)| *max)
        .unwrap_or(0)
}

fn list_cap(field: &str) -> usize {
    LIST_FIELD_CAPS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, max)| *max)
        .unwrap_or(0)
}

/// Decode one string field after checking its decoded size on the raw token,
/// so an oversized string is refused before serde copies it.
fn capped_string<'de, D>(deserializer: D, field: &'static str) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    capped_raw_string(raw.get(), field)
}

fn capped_raw_string<E: de::Error>(raw: &str, field: &'static str) -> Result<String, E> {
    match check_string_bytes(raw, string_cap(field)) {
        Ok(()) => {}
        Err("string exceeds byte cap") => return Err(field_cap_error(field)),
        Err(other) => return Err(E::custom(other)),
    }
    serde_json::from_str(raw).map_err(E::custom)
}

/// `Option<String>` form of [`capped_string`]; `null` decodes as `None`.
fn capped_opt_string<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    if raw.get() == "null" {
        return Ok(None);
    }
    capped_raw_string(raw.get(), field).map(Some)
}

macro_rules! capped_field {
    ($name:ident, $field:literal) => {
        fn $name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
            capped_string(d, $field)
        }
    };
    ($name:ident, opt $field:literal) => {
        fn $name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
            capped_opt_string(d, $field)
        }
    };
}

capped_field!(de_event_id, "event_id");
capped_field!(de_title, "title");
capped_field!(de_description, opt "description");
capped_field!(de_tz, "tz");
capped_field!(de_location, opt "location");
capped_field!(de_organizer, "organizer");
capped_field!(de_color, opt "color");
capped_field!(de_freq, "freq");
capped_field!(de_comment, opt "comment");

/// Deserialize a list of strings with an entry cap and a per-entry byte cap.
/// The visitor counts as it pushes and aborts at `cap + 1`, never
/// pre-allocating from the declared length; each entry's decoded size is
/// checked on the raw token before it is copied. Mirrors
/// `envelope::bounded_references`.
fn bounded_string_list<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ListVisitor(&'static str);

    impl<'de> Visitor<'de> for ListVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "a list of at most {} `{}` entries",
                list_cap(self.0),
                self.0
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<String>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let max = list_cap(self.0);
            let mut out: Vec<String> = Vec::new();
            while let Some(raw) = seq.next_element::<&serde_json::value::RawValue>()? {
                if out.len() >= max {
                    return Err(list_cap_error(self.0));
                }
                out.push(capped_raw_string(raw.get(), self.0)?);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(ListVisitor(field))
}

fn bounded_attendees<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    bounded_string_list(d, "attendees")
}

/// Maximum `BYDAY` entries accepted on the wire. RFC 5545 weekly BYDAY is a
/// subset of the 7 weekdays; 16 gives generous slack while bounding the
/// recurrence expansion. A malicious peer could otherwise send a huge `byday`
/// list, which `expand_occurrences` iterates once per step (up to the 5000-step
/// safety cap) — a quadratic-blowup DoS triggered when the recipient views the
/// event. The cap here rejects it at ingestion, before it is stored or expanded.
pub const MAX_BYDAY: usize = 16;

/// Deserialize the `byday` list capped at [`MAX_BYDAY`] entries of at most
/// [`MAX_BYDAY_CODE_BYTES`] each.
fn bounded_byday<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    bounded_string_list(d, "byday")
}

/// Wire payload for `KIND_CALENDAR_EVENT` (100) and `KIND_CALENDAR_UPDATE` (104).
///
/// Sent by the organizer to each invited attendee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalendarEventPayload {
    /// Unique event identifier (UUID). Used to correlate RSVPs and updates.
    #[serde(deserialize_with = "de_event_id")]
    pub event_id: String,
    /// Event title.
    #[serde(deserialize_with = "de_title")]
    pub title: String,
    /// Optional description / agenda.
    #[serde(default, deserialize_with = "de_description")]
    pub description: Option<String>,
    /// Start time as Unix timestamp milliseconds.
    pub start_ms: u64,
    /// End time as Unix timestamp milliseconds.
    pub end_ms: u64,
    /// IANA timezone identifier (e.g. "UTC", "America/New_York").
    #[serde(deserialize_with = "de_tz")]
    pub tz: String,
    /// Optional location string.
    #[serde(default, deserialize_with = "de_location")]
    pub location: Option<String>,
    /// Node ID (hex) of the organizer.
    #[serde(deserialize_with = "de_organizer")]
    pub organizer: String,
    /// Node IDs (hex) of all invited attendees (including the recipient).
    /// Capped at [`MAX_ATTENDEES`] on the wire.
    #[serde(default, deserialize_with = "bounded_attendees")]
    pub attendees: Vec<String>,
    /// Optional recurrence rule (RFC 5545-inspired).
    #[serde(default)]
    pub recurrence: Option<WireRRule>,
    /// Optional display color (CSS hex, e.g. "#3498db").
    #[serde(default, deserialize_with = "de_color")]
    pub color: Option<String>,
}

impl CalendarEventPayload {
    /// Decode a peer's invite or update under the inbound caps. Order:
    /// aggregate byte cap (no allocation), lexical admission, serde with
    /// pre-copy field caps, then [`Self::validate`]. Nothing is cloned, stored
    /// or expanded before this returns `Ok`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CalendarPayloadError> {
        decode_capped::<Self>(bytes, MAX_CALENDAR_PAYLOAD_BYTES)?.validated()
    }

    fn validated(self) -> Result<Self, CalendarPayloadError> {
        self.validate()?;
        Ok(self)
    }

    /// Check an in-memory payload against the same caps `decode` enforces, so
    /// the owner API can refuse a payload its peers would refuse before it is
    /// stored or paid for. Covers field lengths, list counts, the serialized
    /// byte cap and the recurrence rule's implied size.
    pub fn validate(&self) -> Result<(), CalendarPayloadError> {
        check_len("event_id", &self.event_id)?;
        check_len("title", &self.title)?;
        check_opt_len("description", self.description.as_deref())?;
        check_len("tz", &self.tz)?;
        check_opt_len("location", self.location.as_deref())?;
        check_len("organizer", &self.organizer)?;
        check_opt_len("color", self.color.as_deref())?;
        check_list("attendees", &self.attendees)?;
        if let Some(rule) = &self.recurrence {
            rule.validate(self.start_ms)?;
        }
        check_serialized_len(self, MAX_CALENDAR_PAYLOAD_BYTES)
    }
}

/// Wire recurrence rule — a compact, serde-friendly RFC 5545 subset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireRRule {
    /// Frequency: "DAILY", "WEEKLY", "MONTHLY", or "YEARLY".
    #[serde(deserialize_with = "de_freq")]
    pub freq: String,
    /// Interval between recurrences (default 1).
    #[serde(default = "default_interval")]
    pub interval: u32,
    /// End as Unix timestamp milliseconds. None = no end date.
    #[serde(default)]
    pub until: Option<u64>,
    /// Maximum occurrence count. None = unlimited.
    #[serde(default)]
    pub count: Option<u32>,
    /// Days of the week (e.g. ["MO","WE","FR"]). Empty = no constraint.
    /// Capped at [`MAX_BYDAY`] on the wire to bound recurrence expansion.
    #[serde(default, deserialize_with = "bounded_byday")]
    pub byday: Vec<String>,
}

fn default_interval() -> u32 {
    1
}

const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

impl WireRRule {
    /// Refuse a rule that is malformed or whose implied size exceeds
    /// [`MAX_RECURRENCE_INSTANCES`]. See [`Self::implied_instances`].
    pub fn validate(&self, start_ms: u64) -> Result<(), CalendarPayloadError> {
        check_len("freq", &self.freq)?;
        check_list("byday", &self.byday)?;
        if self.interval == 0 {
            return Err(CalendarPayloadError::RecurrenceInvalid(
                "interval must be at least 1",
            ));
        }
        if !matches!(
            self.freq.as_str(),
            "DAILY" | "WEEKLY" | "MONTHLY" | "YEARLY"
        ) {
            return Err(CalendarPayloadError::RecurrenceInvalid("unknown freq"));
        }
        match self.implied_instances(start_ms) {
            Some(estimated) if estimated > MAX_RECURRENCE_INSTANCES => {
                Err(CalendarPayloadError::RecurrenceTooLarge {
                    estimated,
                    max: MAX_RECURRENCE_INSTANCES,
                })
            }
            _ => Ok(()),
        }
    }

    /// Upper bound on the occurrences this rule can produce, from `COUNT`
    /// and/or `UNTIL`, computed without expanding anything. `None` means the
    /// rule is open-ended (neither `COUNT` nor `UNTIL`) and the reader's
    /// window bounds it. The `UNTIL` estimate uses the shortest period a
    /// frequency can have (28-day months, 365-day years) and counts every
    /// `BYDAY` entry per weekly step, so it never under-counts the expander.
    pub fn implied_instances(&self, start_ms: u64) -> Option<u64> {
        let by_until = self.until.map(|until| {
            let unit_ms = match self.freq.as_str() {
                "WEEKLY" => 7 * MS_PER_DAY,
                "MONTHLY" => 28 * MS_PER_DAY,
                "YEARLY" => 365 * MS_PER_DAY,
                _ => MS_PER_DAY,
            };
            let period_ms = unit_ms.saturating_mul(u64::from(self.interval.max(1)));
            let steps = until.saturating_sub(start_ms) / period_ms + 1;
            let per_step = if self.freq == "WEEKLY" {
                self.byday.len().max(1) as u64
            } else {
                1
            };
            steps.saturating_mul(per_step)
        });
        match (self.count.map(u64::from), by_until) {
            (Some(count), Some(until)) => Some(count.min(until)),
            (Some(count), None) => Some(count),
            (None, Some(until)) => Some(until),
            (None, None) => None,
        }
    }
}

/// Byte cap first, then lexical admission, then serde with pre-copy caps.
/// Classifies pre-copy cap refusals by their static marker; every other serde
/// diagnostic is discarded as `Malformed` because it can echo peer input.
fn decode_capped<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    max_bytes: usize,
) -> Result<T, CalendarPayloadError> {
    if bytes.len() > max_bytes {
        return Err(CalendarPayloadError::TooLarge {
            actual: bytes.len(),
            max: max_bytes,
        });
    }
    wire_json::check_payload(bytes, &[]).map_err(|_| CalendarPayloadError::Malformed)?;
    serde_json::from_slice(bytes).map_err(|e| classify_serde_error(&e.to_string()))
}

fn classify_serde_error(message: &str) -> CalendarPayloadError {
    fn marked(message: &str, marker: &str) -> Option<&'static str> {
        let rest = message.strip_prefix(marker)?;
        let name = rest.split_whitespace().next()?;
        STRING_FIELD_CAPS
            .iter()
            .chain(LIST_FIELD_CAPS.iter())
            .map(|(field, _)| *field)
            .find(|field| *field == name)
    }
    if let Some(field) = marked(message, CAP_FIELD_MARKER) {
        return CalendarPayloadError::FieldTooLong {
            field,
            max: string_cap(field),
        };
    }
    if let Some(field) = marked(message, CAP_LIST_MARKER) {
        return CalendarPayloadError::TooManyEntries {
            field,
            max: list_cap(field),
        };
    }
    CalendarPayloadError::Malformed
}

fn check_len(field: &'static str, value: &str) -> Result<(), CalendarPayloadError> {
    let max = string_cap(field);
    if value.len() > max {
        return Err(CalendarPayloadError::FieldTooLong { field, max });
    }
    Ok(())
}

fn check_opt_len(field: &'static str, value: Option<&str>) -> Result<(), CalendarPayloadError> {
    value.map_or(Ok(()), |v| check_len(field, v))
}

fn check_list(field: &'static str, values: &[String]) -> Result<(), CalendarPayloadError> {
    let max = list_cap(field);
    if values.len() > max {
        return Err(CalendarPayloadError::TooManyEntries { field, max });
    }
    for value in values {
        check_len(field, value)?;
    }
    Ok(())
}

fn check_serialized_len<T: Serialize>(value: &T, max: usize) -> Result<(), CalendarPayloadError> {
    let actual = serde_json::to_vec(value)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if actual > max {
        return Err(CalendarPayloadError::TooLarge { actual, max });
    }
    Ok(())
}

/// Wire payload for `KIND_RSVP` (101).
///
/// Sent by an attendee back to the organizer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RsvpPayload {
    /// The `event_id` from the original `CalendarEventPayload`.
    #[serde(deserialize_with = "de_event_id")]
    pub event_id: String,
    /// RSVP response.
    pub response: RsvpResponse,
    /// Optional free-text comment from the attendee.
    #[serde(default, deserialize_with = "de_comment")]
    pub comment: Option<String>,
}

impl RsvpPayload {
    /// Decode a peer's RSVP under the inbound caps; see
    /// [`CalendarEventPayload::decode`] for the order of checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, CalendarPayloadError> {
        let payload = decode_capped::<Self>(bytes, MAX_RSVP_PAYLOAD_BYTES)?;
        payload.validate()?;
        Ok(payload)
    }

    /// Check an in-memory RSVP against the same caps `decode` enforces.
    pub fn validate(&self) -> Result<(), CalendarPayloadError> {
        check_len("event_id", &self.event_id)?;
        check_opt_len("comment", self.comment.as_deref())?;
        check_serialized_len(self, MAX_RSVP_PAYLOAD_BYTES)
    }
}

/// RSVP response options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpResponse {
    /// Accepted / attending.
    Accepted,
    /// Declined / not attending.
    Declined,
    /// Tentative / maybe attending.
    Tentative,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid weekly BYDAY (<= MAX_BYDAY) round-trips through JSON unchanged.
    #[test]
    fn byday_within_cap_roundtrips() {
        let json = r#"{"freq":"WEEKLY","byday":["MO","WE","FR"]}"#;
        let rule: WireRRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.byday, vec!["MO", "WE", "FR"]);
    }

    /// An oversized BYDAY list is rejected at deserialization (DoS guard),
    /// bounding the recurrence expansion regardless of a hostile peer's input.
    #[test]
    fn oversized_byday_is_rejected() {
        let big: Vec<String> = vec!["MO".to_string(); MAX_BYDAY + 1];
        let json = serde_json::to_string(&serde_json::json!({
            "freq": "WEEKLY",
            "byday": big,
        }))
        .unwrap();
        let err = serde_json::from_str::<WireRRule>(&json).unwrap_err();
        assert_eq!(
            classify_serde_error(&err.to_string()),
            CalendarPayloadError::TooManyEntries {
                field: "byday",
                max: MAX_BYDAY
            }
        );
    }

    #[test]
    fn event_payload_roundtrip() {
        let p = CalendarEventPayload {
            event_id: "evt-abc".to_string(),
            title: "Design Review".to_string(),
            description: Some("Discuss v2 arch".to_string()),
            start_ms: 1_700_000_000_000,
            end_ms: 1_700_003_600_000,
            tz: "UTC".to_string(),
            location: None,
            organizer: "aabb".to_string(),
            attendees: vec!["ccdd".to_string()],
            recurrence: None,
            color: Some("#e74c3c".to_string()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: CalendarEventPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn rsvp_payload_roundtrip() {
        let r = RsvpPayload {
            event_id: "evt-abc".to_string(),
            response: RsvpResponse::Accepted,
            comment: Some("Looking forward to it!".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: RsvpPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn rsvp_response_serialization() {
        assert_eq!(
            serde_json::to_string(&RsvpResponse::Accepted).unwrap(),
            "\"accepted\""
        );
        assert_eq!(
            serde_json::to_string(&RsvpResponse::Declined).unwrap(),
            "\"declined\""
        );
        assert_eq!(
            serde_json::to_string(&RsvpResponse::Tentative).unwrap(),
            "\"tentative\""
        );
    }

    #[test]
    fn wire_rrule_defaults() {
        let json = r#"{"freq":"WEEKLY"}"#;
        let rule: WireRRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.interval, 1);
        assert!(rule.until.is_none());
        assert!(rule.count.is_none());
        assert!(rule.byday.is_empty());
    }

    fn sample_event() -> CalendarEventPayload {
        CalendarEventPayload {
            event_id: "evt-abc".to_string(),
            title: "Design Review".to_string(),
            description: Some("Discuss v2 arch".to_string()),
            start_ms: 1_700_000_000_000,
            end_ms: 1_700_003_600_000,
            tz: "UTC".to_string(),
            location: Some("Room 4".to_string()),
            organizer: "aa".repeat(32),
            attendees: vec!["bb".repeat(32), "cc".repeat(32)],
            recurrence: None,
            color: Some("#e74c3c".to_string()),
        }
    }

    fn decode_json(value: serde_json::Value) -> Result<CalendarEventPayload, CalendarPayloadError> {
        CalendarEventPayload::decode(&serde_json::to_vec(&value).unwrap())
    }

    fn with_recurrence(rule: serde_json::Value) -> serde_json::Value {
        let mut v = serde_json::to_value(sample_event()).unwrap();
        v["recurrence"] = rule;
        v
    }

    // ── Inbound caps ────────────────────────────────────────────────────

    /// In-cap invites decode to the same value the sender serialized.
    #[test]
    fn decode_within_caps_roundtrips() {
        let p = sample_event();
        let decoded = CalendarEventPayload::decode(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(p, decoded);
        assert!(p.validate().is_ok());
    }

    /// The largest payload the owner API can build stays inside the byte cap.
    #[test]
    fn maximal_honest_payload_fits_byte_cap() {
        let p = CalendarEventPayload {
            event_id: "e".repeat(MAX_EVENT_ID_BYTES),
            title: "t".repeat(MAX_TITLE_BYTES),
            description: Some("d".repeat(MAX_DESCRIPTION_BYTES)),
            tz: "z".repeat(MAX_TZ_BYTES),
            location: Some("l".repeat(MAX_LOCATION_BYTES)),
            organizer: "a".repeat(MAX_NODE_ID_HEX_BYTES),
            attendees: vec!["b".repeat(MAX_NODE_ID_HEX_BYTES); MAX_ATTENDEES],
            recurrence: Some(WireRRule {
                freq: "WEEKLY".into(),
                interval: 1,
                until: None,
                count: Some(MAX_RECURRENCE_INSTANCES as u32),
                byday: vec!["MO".into(); MAX_BYDAY],
            }),
            color: Some("c".repeat(MAX_COLOR_BYTES)),
            ..sample_event()
        };
        let bytes = serde_json::to_vec(&p).unwrap();
        assert!(
            bytes.len() <= MAX_CALENDAR_PAYLOAD_BYTES,
            "{} bytes",
            bytes.len()
        );
        assert_eq!(CalendarEventPayload::decode(&bytes).unwrap(), p);
    }

    /// The aggregate byte cap is the first check: a payload one byte over it
    /// is refused as `TooLarge` without being parsed.
    #[test]
    fn oversized_payload_is_too_large() {
        let bytes = vec![b' '; MAX_CALENDAR_PAYLOAD_BYTES + 1];
        assert_eq!(
            CalendarEventPayload::decode(&bytes),
            Err(CalendarPayloadError::TooLarge {
                actual: MAX_CALENDAR_PAYLOAD_BYTES + 1,
                max: MAX_CALENDAR_PAYLOAD_BYTES
            })
        );
        let bytes = vec![b' '; MAX_RSVP_PAYLOAD_BYTES + 1];
        assert_eq!(
            RsvpPayload::decode(&bytes),
            Err(CalendarPayloadError::TooLarge {
                actual: MAX_RSVP_PAYLOAD_BYTES + 1,
                max: MAX_RSVP_PAYLOAD_BYTES
            })
        );
    }

    /// Each string field has a pre-copy byte cap and names itself in the refusal.
    #[test]
    fn oversized_string_fields_are_refused_by_name() {
        for (field, max) in [
            ("event_id", MAX_EVENT_ID_BYTES),
            ("title", MAX_TITLE_BYTES),
            ("description", MAX_DESCRIPTION_BYTES),
            ("tz", MAX_TZ_BYTES),
            ("location", MAX_LOCATION_BYTES),
            ("organizer", MAX_NODE_ID_HEX_BYTES),
            ("color", MAX_COLOR_BYTES),
        ] {
            let mut v = serde_json::to_value(sample_event()).unwrap();
            v[field] = serde_json::Value::String("x".repeat(max + 1));
            assert_eq!(
                decode_json(v),
                Err(CalendarPayloadError::FieldTooLong { field, max }),
                "field {field}"
            );
        }
        // Escapes count by decoded size, so an escaped over-cap string is
        // refused too, and an escaped in-cap string is accepted.
        let over = format!(
            r#"{{"event_id":"e","title":"{}","start_ms":1,"end_ms":2,"tz":"UTC","organizer":"aa"}}"#,
            r"x".repeat(MAX_TITLE_BYTES + 1)
        );
        assert_eq!(
            CalendarEventPayload::decode(over.as_bytes()),
            Err(CalendarPayloadError::FieldTooLong {
                field: "title",
                max: MAX_TITLE_BYTES
            })
        );
        let exact = format!(
            r#"{{"event_id":"e","title":"{}","start_ms":1,"end_ms":2,"tz":"UTC","organizer":"aa"}}"#,
            r"x".repeat(MAX_TITLE_BYTES)
        );
        let p = CalendarEventPayload::decode(exact.as_bytes()).unwrap();
        assert_eq!(p.title.len(), MAX_TITLE_BYTES);
    }

    /// The attendee list is capped by count and each entry by size; a
    /// declared length never pre-allocates.
    #[test]
    fn oversized_attendee_list_is_refused() {
        let mut v = serde_json::to_value(sample_event()).unwrap();
        v["attendees"] = serde_json::json!(vec!["bb".repeat(32); MAX_ATTENDEES + 1]);
        assert_eq!(
            decode_json(v),
            Err(CalendarPayloadError::TooManyEntries {
                field: "attendees",
                max: MAX_ATTENDEES
            })
        );
        let mut v = serde_json::to_value(sample_event()).unwrap();
        v["attendees"] = serde_json::json!(["b".repeat(MAX_NODE_ID_HEX_BYTES + 1)]);
        assert_eq!(
            decode_json(v),
            Err(CalendarPayloadError::FieldTooLong {
                field: "attendees",
                max: MAX_NODE_ID_HEX_BYTES
            })
        );
        let mut v = serde_json::to_value(sample_event()).unwrap();
        v["attendees"] = serde_json::json!(vec!["bb".repeat(32); MAX_ATTENDEES]);
        assert_eq!(decode_json(v).unwrap().attendees.len(), MAX_ATTENDEES);
    }

    /// Exactly one event per payload: a batch is refused as malformed.
    #[test]
    fn batch_of_events_is_refused() {
        assert_eq!(MAX_EVENTS_PER_PAYLOAD, 1);
        let batch = serde_json::json!([sample_event(), sample_event()]);
        assert_eq!(decode_json(batch), Err(CalendarPayloadError::Malformed));
        assert_eq!(
            CalendarEventPayload::decode(b"not json"),
            Err(CalendarPayloadError::Malformed)
        );
    }

    /// A recurrence whose COUNT, or UNTIL span, implies more than the cap is
    /// refused at decode; nothing is expanded to find out.
    #[test]
    fn recurrence_past_cap_is_refused() {
        let start = sample_event().start_ms;
        let max = MAX_RECURRENCE_INSTANCES;
        // COUNT one over the cap.
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "DAILY", "count": max + 1
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::RecurrenceTooLarge {
                estimated: max + 1,
                max
            }
        );
        assert_eq!(err.code(), "calendar_recurrence_too_large");
        assert!(err.is_cap());
        // UNTIL spanning (cap + 1) days, daily.
        let until = start + max * MS_PER_DAY;
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "DAILY", "until": until
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::RecurrenceTooLarge {
                estimated: max + 1,
                max
            }
        );
        // Weekly with BYDAY multiplies per step: 16 codes x 313 weeks > cap.
        let until = start + 312 * 7 * MS_PER_DAY;
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "WEEKLY", "until": until, "byday": vec!["MO"; MAX_BYDAY]
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::RecurrenceTooLarge {
                estimated: 313 * MAX_BYDAY as u64,
                max
            }
        );
        // A COUNT inside the cap bounds an otherwise over-cap UNTIL span.
        let p = decode_json(with_recurrence(serde_json::json!({
            "freq": "DAILY", "until": start + 10 * max * MS_PER_DAY, "count": max
        })))
        .unwrap();
        assert_eq!(p.recurrence.unwrap().implied_instances(start), Some(max));
    }

    /// In-cap and open-ended rules are admitted; the reader's window bounds
    /// an open-ended series.
    #[test]
    fn recurrence_within_cap_is_admitted() {
        let start = sample_event().start_ms;
        let p = decode_json(with_recurrence(serde_json::json!({
            "freq": "WEEKLY", "byday": ["MO", "WE", "FR"]
        })))
        .unwrap();
        assert_eq!(
            p.recurrence.as_ref().unwrap().implied_instances(start),
            None
        );
        let p = decode_json(with_recurrence(serde_json::json!({
            "freq": "DAILY", "count": MAX_RECURRENCE_INSTANCES
        })))
        .unwrap();
        assert_eq!(
            p.recurrence.unwrap().implied_instances(start),
            Some(MAX_RECURRENCE_INSTANCES)
        );
        // Ten years of monthly: 28-day months over-count to 131, still in cap.
        let p = decode_json(with_recurrence(serde_json::json!({
            "freq": "MONTHLY", "until": start + 3650 * MS_PER_DAY
        })))
        .unwrap();
        assert_eq!(p.recurrence.unwrap().implied_instances(start), Some(131));
        // A huge interval saturates the period rather than overflowing.
        let p = decode_json(with_recurrence(serde_json::json!({
            "freq": "YEARLY", "interval": u32::MAX, "until": u64::MAX
        })))
        .unwrap();
        assert!(p.recurrence.unwrap().implied_instances(start).unwrap() <= 2);
    }

    /// The decode-time estimate never under-counts the expander: for bounded
    /// rules across every frequency, interval and BYDAY shape, the occurrences
    /// `expand_occurrences` produces over an unbounded window never exceed
    /// `implied_instances`. An admitted series can therefore never be larger
    /// than the cap says when it is viewed.
    #[test]
    fn implied_instances_bounds_the_expander() {
        use crate::calendar::{expand_occurrences, CalendarEvent, Freq, RRule};
        let start = 1_700_000_000_000u64; // 2023-11-14, a Tuesday
        let bydays: [&[&str]; 3] = [
            &[],
            &["MO", "WE", "FR"],
            &["MO", "MO", "SU", "SA", "TU", "TU"],
        ];
        let mut checked = 0;
        for (freq, name) in [
            (Freq::Daily, "DAILY"),
            (Freq::Weekly, "WEEKLY"),
            (Freq::Monthly, "MONTHLY"),
            (Freq::Yearly, "YEARLY"),
        ] {
            for interval in [1u32, 2, 5] {
                for byday in bydays {
                    for (until, count) in [
                        (Some(start + 400 * MS_PER_DAY), None),
                        (Some(start + 3 * 365 * MS_PER_DAY), Some(37)),
                        (None, Some(123)),
                        (Some(start), None),
                    ] {
                        let wire = WireRRule {
                            freq: name.into(),
                            interval,
                            until,
                            count,
                            byday: byday.iter().map(|s| s.to_string()).collect(),
                        };
                        let implied = wire.implied_instances(start).expect("bounded rule");
                        let event = CalendarEvent {
                            id: "e".into(),
                            organizer: "o".into(),
                            title: "t".into(),
                            description: None,
                            start,
                            end: start + 3_600_000,
                            tz: "Europe/Copenhagen".into(),
                            location: None,
                            attendees: vec![],
                            recurrence: Some(RRule {
                                freq,
                                interval,
                                until,
                                count,
                                byday: wire.byday.clone(),
                                bymonthday: vec![],
                            }),
                            color: None,
                            created_at: String::new(),
                            parent_id: None,
                        };
                        let expanded =
                            expand_occurrences(&event, 0, u64::MAX / 2, &[]).len() as u64;
                        assert!(
                            expanded <= implied,
                            "{name} interval {interval} byday {byday:?} until {until:?} count {count:?}: expanded {expanded} > implied {implied}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 4 * 3 * 3 * 4);
    }

    /// Malformed rules are refused with a typed reason instead of being
    /// stored and silently producing no occurrences.
    #[test]
    fn invalid_recurrence_is_refused() {
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "DAILY", "interval": 0
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::RecurrenceInvalid("interval must be at least 1")
        );
        assert!(!err.is_cap());
        let err =
            decode_json(with_recurrence(serde_json::json!({ "freq": "HOURLY" }))).unwrap_err();
        assert_eq!(err, CalendarPayloadError::RecurrenceInvalid("unknown freq"));
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "x".repeat(MAX_FREQ_BYTES + 1)
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::FieldTooLong {
                field: "freq",
                max: MAX_FREQ_BYTES
            }
        );
        let err = decode_json(with_recurrence(serde_json::json!({
            "freq": "WEEKLY", "byday": ["x".repeat(MAX_BYDAY_CODE_BYTES + 1)]
        })))
        .unwrap_err();
        assert_eq!(
            err,
            CalendarPayloadError::FieldTooLong {
                field: "byday",
                max: MAX_BYDAY_CODE_BYTES
            }
        );
    }

    /// RSVPs have their own, smaller caps.
    #[test]
    fn rsvp_caps() {
        let ok = RsvpPayload {
            event_id: "evt".into(),
            response: RsvpResponse::Tentative,
            comment: Some("c".repeat(MAX_RSVP_COMMENT_BYTES)),
        };
        assert_eq!(
            RsvpPayload::decode(&serde_json::to_vec(&ok).unwrap()).unwrap(),
            ok
        );
        let long = RsvpPayload {
            comment: Some("c".repeat(MAX_RSVP_COMMENT_BYTES + 1)),
            ..ok.clone()
        };
        assert_eq!(
            RsvpPayload::decode(&serde_json::to_vec(&long).unwrap()),
            Err(CalendarPayloadError::FieldTooLong {
                field: "comment",
                max: MAX_RSVP_COMMENT_BYTES
            })
        );
        assert_eq!(
            long.validate().unwrap_err().code(),
            "calendar_field_too_long"
        );
        let long_id = RsvpPayload {
            event_id: "e".repeat(MAX_EVENT_ID_BYTES + 1),
            ..ok
        };
        assert_eq!(
            RsvpPayload::decode(&serde_json::to_vec(&long_id).unwrap()),
            Err(CalendarPayloadError::FieldTooLong {
                field: "event_id",
                max: MAX_EVENT_ID_BYTES
            })
        );
    }

    /// `validate` (the owner-side check) agrees with `decode` on in-memory values.
    #[test]
    fn validate_matches_decode() {
        let mut p = sample_event();
        p.attendees = vec!["bb".repeat(32); MAX_ATTENDEES + 1];
        assert_eq!(
            p.validate(),
            Err(CalendarPayloadError::TooManyEntries {
                field: "attendees",
                max: MAX_ATTENDEES
            })
        );
        let mut p = sample_event();
        p.description = Some("d".repeat(MAX_DESCRIPTION_BYTES + 1));
        assert_eq!(
            p.validate(),
            Err(CalendarPayloadError::FieldTooLong {
                field: "description",
                max: MAX_DESCRIPTION_BYTES
            })
        );
        let mut p = sample_event();
        p.recurrence = Some(WireRRule {
            freq: "DAILY".into(),
            interval: 1,
            until: None,
            count: Some(MAX_RECURRENCE_INSTANCES as u32 + 1),
            byday: vec![],
        });
        assert!(matches!(
            p.validate(),
            Err(CalendarPayloadError::RecurrenceTooLarge { .. })
        ));
    }

    /// Refusal codes are stable identifiers and never carry peer text.
    #[test]
    fn refusal_codes_are_stable() {
        let cases = [
            (
                CalendarPayloadError::TooLarge { actual: 1, max: 0 },
                "calendar_too_large",
            ),
            (
                CalendarPayloadError::FieldTooLong {
                    field: "title",
                    max: 0,
                },
                "calendar_field_too_long",
            ),
            (
                CalendarPayloadError::TooManyEntries {
                    field: "byday",
                    max: 0,
                },
                "calendar_too_many_entries",
            ),
            (
                CalendarPayloadError::RecurrenceTooLarge {
                    estimated: 1,
                    max: 0,
                },
                "calendar_recurrence_too_large",
            ),
            (
                CalendarPayloadError::RecurrenceInvalid("x"),
                "calendar_recurrence_invalid",
            ),
            (CalendarPayloadError::Malformed, "calendar_malformed"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            assert!(
                CalendarPayloadError::CODES.contains(&code),
                "{code} missing from CODES"
            );
            assert!(!err.to_string().is_empty());
        }
        assert_eq!(CalendarPayloadError::CODES.len(), cases.len());
        // Unknown marker text (never produced) is Malformed, not a cap.
        assert_eq!(
            classify_serde_error("calendar cap field:nope at line 1"),
            CalendarPayloadError::Malformed
        );
        assert_eq!(
            classify_serde_error("missing field `title`"),
            CalendarPayloadError::Malformed
        );
    }

    #[test]
    fn event_payload_no_recurrence_defaults() {
        let json =
            r#"{"event_id":"e1","title":"T","start_ms":1,"end_ms":2,"tz":"UTC","organizer":"aa"}"#;
        let p: CalendarEventPayload = serde_json::from_str(json).unwrap();
        assert!(p.recurrence.is_none());
        assert!(p.description.is_none());
        assert!(p.location.is_none());
        assert!(p.color.is_none());
        assert!(p.attendees.is_empty());
    }
}
