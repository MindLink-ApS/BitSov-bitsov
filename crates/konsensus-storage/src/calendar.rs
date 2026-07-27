//! Calendar storage models — CalendarEventRecord and RsvpRecord.
//!
//! These types are populated by the message handler after decrypting
//! incoming KIND_CALENDAR_EVENT / KIND_RSVP envelopes, and by the API
//! handler when the local user creates events.

use serde::{Deserialize, Serialize};

/// A stored calendar event, populated from a decrypted `CalendarEventPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEventRecord {
    /// Unique event identifier (UUID). Matches the wire `event_id`.
    pub id: String,
    /// Associated UKM message ID (hex), if received via P2P. `None` for local events.
    pub message_id: Option<String>,
    /// Organizer node ID (hex).
    pub organizer: String,
    /// Event title.
    pub title: String,
    /// Optional description / agenda.
    pub description: Option<String>,
    /// Start time (Unix ms).
    pub start_ms: u64,
    /// End time (Unix ms).
    pub end_ms: u64,
    /// IANA timezone (e.g. "UTC").
    pub tz: String,
    /// Optional location string.
    pub location: Option<String>,
    /// JSON array of attendee node IDs (hex).
    pub attendees_json: String,
    /// JSON-serialized `WireRRule`, or `None` for non-recurring events.
    pub recurrence_json: Option<String>,
    /// Optional CSS hex color.
    pub color: Option<String>,
    /// ISO 8601 creation timestamp (set by DB default on first insert).
    pub created_at: String,
    pub parent_id: Option<String>,
}

/// A stored RSVP response from an attendee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsvpRecord {
    /// Unique RSVP identifier (UUID).
    pub id: String,
    /// The event this RSVP belongs to.
    pub event_id: String,
    /// Responder node ID (hex).
    pub responder: String,
    /// Response string: `"accepted"`, `"declined"`, or `"tentative"`.
    pub response: String,
    /// Optional free-text comment from the attendee.
    pub comment: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}
