//! Calendar wire payloads — inside the UKM envelope ciphertext for kinds 100-101 and 104.
//!
//! These structs are serialized to JSON, E2EE encrypted via Double Ratchet,
//! and placed in the `ciphertext` field of UKM envelopes.

use serde::{Deserialize, Serialize};

/// Wire payload for `KIND_CALENDAR_EVENT` (100) and `KIND_CALENDAR_UPDATE` (104).
///
/// Sent by the organizer to each invited attendee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalendarEventPayload {
    /// Unique event identifier (UUID). Used to correlate RSVPs and updates.
    pub event_id: String,
    /// Event title.
    pub title: String,
    /// Optional description / agenda.
    #[serde(default)]
    pub description: Option<String>,
    /// Start time as Unix timestamp milliseconds.
    pub start_ms: u64,
    /// End time as Unix timestamp milliseconds.
    pub end_ms: u64,
    /// IANA timezone identifier (e.g. "UTC", "America/New_York").
    pub tz: String,
    /// Optional location string.
    #[serde(default)]
    pub location: Option<String>,
    /// Node ID (hex) of the organizer.
    pub organizer: String,
    /// Node IDs (hex) of all invited attendees (including the recipient).
    #[serde(default)]
    pub attendees: Vec<String>,
    /// Optional recurrence rule (RFC 5545-inspired).
    #[serde(default)]
    pub recurrence: Option<WireRRule>,
    /// Optional display color (CSS hex, e.g. "#3498db").
    #[serde(default)]
    pub color: Option<String>,
}

/// Wire recurrence rule — a compact, serde-friendly RFC 5545 subset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireRRule {
    /// Frequency: "DAILY", "WEEKLY", "MONTHLY", or "YEARLY".
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
    #[serde(default)]
    pub byday: Vec<String>,
}

fn default_interval() -> u32 {
    1
}

/// Wire payload for `KIND_RSVP` (101).
///
/// Sent by an attendee back to the organizer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RsvpPayload {
    /// The `event_id` from the original `CalendarEventPayload`.
    pub event_id: String,
    /// RSVP response.
    pub response: RsvpResponse,
    /// Optional free-text comment from the attendee.
    #[serde(default)]
    pub comment: Option<String>,
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

    #[test]
    fn event_payload_no_recurrence_defaults() {
        let json = r#"{"event_id":"e1","title":"T","start_ms":1,"end_ms":2,"tz":"UTC","organizer":"aa"}"#;
        let p: CalendarEventPayload = serde_json::from_str(json).unwrap();
        assert!(p.recurrence.is_none());
        assert!(p.description.is_none());
        assert!(p.location.is_none());
        assert!(p.color.is_none());
        assert!(p.attendees.is_empty());
    }
}
