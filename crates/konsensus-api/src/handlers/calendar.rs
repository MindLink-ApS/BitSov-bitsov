//! Calendar endpoints — create, list, update, delete events, and RSVP.
//!
//! Calendar events are sent as UKM envelopes with KIND_CALENDAR_EVENT (100).
//! RSVPs use KIND_RSVP (101) and updates use KIND_CALENDAR_UPDATE (104).
//! All messages pass through the payment gate (Principle 2).

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::calendar::{CalendarEvent, Freq, RRule};
use konsensus_core::calendar::expand_occurrences as core_expand_occurrences;
use konsensus_core::kind::{KIND_CALENDAR_EVENT, KIND_CALENDAR_UPDATE, KIND_RSVP};
use konsensus_core::payloads::calendar::{CalendarEventPayload, RsvpPayload, RsvpResponse, WireRRule};
use konsensus_core::types::{NodeId, Recipient};
use konsensus_crypto::ratchet_message_to_bytes;
use konsensus_storage::{CalendarEventRecord, RsvpRecord};

use crate::audit::events;
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::handlers::messages::create_payment_proof;
use crate::state::AppState;

// ── Request / Response types ────────────────────────────────────────────

/// Query parameters for `GET /api/v1/calendar/events`.
#[derive(Deserialize)]
pub struct ListEventsQuery {
    /// Start of the time window (Unix ms). Defaults to now.
    #[serde(default)]
    pub from: Option<u64>,
    /// End of the time window (Unix ms). Defaults to 30 days from now.
    #[serde(default)]
    pub to: Option<u64>,
    /// Maximum number of events to return (capped at 500).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// Optional recurrence rule in API requests.
#[derive(Debug, Deserialize)]
pub struct ApiRRule {
    pub freq: String,
    #[serde(default = "default_interval")]
    pub interval: u32,
    pub until: Option<u64>,
    pub count: Option<u32>,
    #[serde(default)]
    pub byday: Vec<String>,
}

fn default_interval() -> u32 {
    1
}

/// Request body for `POST /api/v1/calendar/events`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEventRequest {
    pub title: String,
    pub description: Option<String>,
    /// Start time (Unix ms).
    pub start: u64,
    /// End time (Unix ms).
    pub end: u64,
    /// IANA timezone (e.g. "UTC").
    #[serde(default = "default_tz")]
    pub tz: String,
    pub location: Option<String>,
    /// Recipient node IDs (hex) to invite. At least one required.
    pub attendees: Vec<String>,
    pub recurrence: Option<ApiRRule>,
    pub color: Option<String>,
}

fn default_tz() -> String {
    "UTC".to_string()
}

/// Request body for `PUT /api/v1/calendar/events/:id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEventRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub tz: Option<String>,
    pub location: Option<String>,
    pub recurrence: Option<ApiRRule>,
    pub color: Option<String>,
}

/// Request body for `POST /api/v1/calendar/events/:id/rsvp`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRsvpRequest {
    /// "accepted", "declined", or "tentative".
    pub response: String,
    pub comment: Option<String>,
    /// Organizer node ID (hex) — needed to route the RSVP back.
    pub organizer: String,
}

/// Event data in API responses.
#[derive(Serialize)]
pub struct EventResponse {
    pub id: String,
    pub message_id: Option<String>,
    pub organizer: String,
    pub title: String,
    pub description: Option<String>,
    pub start: u64,
    pub end: u64,
    pub tz: String,
    pub location: Option<String>,
    pub attendees: Vec<String>,
    pub recurrence: Option<serde_json::Value>,
    pub color: Option<String>,
    pub created_at: String,
}

impl TryFrom<CalendarEventRecord> for EventResponse {
    type Error = ApiError;

    fn try_from(r: CalendarEventRecord) -> Result<Self, Self::Error> {
        let attendees: Vec<String> = serde_json::from_str(&r.attendees_json)
            .map_err(|e| ApiError::Internal(format!("attendees deserialization: {e}")))?;
        let recurrence = r
            .recurrence_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| ApiError::Internal(format!("recurrence deserialization: {e}")))?;
        Ok(Self {
            id: r.id,
            message_id: r.message_id,
            organizer: r.organizer,
            title: r.title,
            description: r.description,
            start: r.start_ms,
            end: r.end_ms,
            tz: r.tz,
            location: r.location,
            attendees,
            recurrence,
            color: r.color,
            created_at: r.created_at,
        })
    }
}

/// Response for create / update operations.
#[derive(Serialize)]
pub struct EventActionResponse {
    pub event_id: String,
    pub message_id: Option<String>,
    pub delivered_to: Vec<String>,
    pub queued_for: Vec<String>,
    pub amount_msat: u64,
}

/// Response for RSVP.
#[derive(Serialize)]
pub struct RsvpActionResponse {
    pub event_id: String,
    pub response: String,
    pub message_id: String,
    pub delivered: bool,
    pub amount_msat: u64,
}

// ── Recurrence bridge ────────────────────────────────────────────────────

/// Expand a recurring [`CalendarEventRecord`] into occurrence start timestamps
/// within the half-open window `[from, to)` (Unix ms, signed for API compat).
///
/// Converts the storage record to the core domain type, maps the wire `RRule`,
/// and delegates to [`core_expand_occurrences`] which is DST-safe via
/// `chrono-tz` (wall-clock arithmetic). Exception suppression is the caller's
/// responsibility — handled in [`list_events`], not here.
///
/// Returns an empty `Vec` when:
/// - `recurrence_json` is absent or unparseable
/// - the frequency string is unrecognised
/// - `to <= 0`
fn expand_occurrences(event: &CalendarEventRecord, from: i64, to: i64) -> Vec<i64> {
    // Parse stored WireRRule.
    let wire: WireRRule = match event.recurrence_json.as_deref() {
        Some(json) => match serde_json::from_str(json) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
        None => return Vec::new(),
    };

    // Map frequency string to domain enum.
    let freq = match wire.freq.as_str() {
        "DAILY" => Freq::Daily,
        "WEEKLY" => Freq::Weekly,
        "MONTHLY" => Freq::Monthly,
        "YEARLY" => Freq::Yearly,
        _ => return Vec::new(),
    };

    let rule = RRule {
        freq,
        interval: wire.interval,
        until: wire.until,
        count: wire.count,
        byday: wire.byday,
        bymonthday: Vec::new(), // WireRRule does not carry BYMONTHDAY
    };

    let attendees: Vec<String> =
        serde_json::from_str(&event.attendees_json).unwrap_or_default();

    let domain = CalendarEvent {
        id: event.id.clone(),
        organizer: event.organizer.clone(),
        title: event.title.clone(),
        description: event.description.clone(),
        start: event.start_ms,
        end: event.end_ms,
        tz: event.tz.clone(),
        location: event.location.clone(),
        attendees,
        recurrence: Some(rule),
        color: event.color.clone(),
        created_at: event.created_at.clone(),
        parent_id: event.parent_id.clone(),
    };

    let from_u64 = if from < 0 { 0u64 } else { from as u64 };
    let to_u64 = if to <= 0 {
        return Vec::new();
    } else {
        to as u64
    };

    // Exceptions are suppressed at the list_events level; pass none here.
    core_expand_occurrences(&domain, from_u64, to_u64, &[])
        .into_iter()
        .map(|occ| occ.start as i64)
        .collect()
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `GET /api/v1/calendar/events` — list events in a time range.
///
/// Returns one-off events plus expanded occurrences of any recurring master
/// events that overlap `[from_ms, to_ms)`. Exception/override records (those
/// with a `parent_id`) suppress the matching computed occurrence and are
/// included verbatim in the response instead.
async fn list_events(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListEventsQuery>,
) -> Result<Json<Vec<EventResponse>>, ApiError> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let from_ms = params.from.unwrap_or(now_ms);
    let to_ms = params.to.unwrap_or(from_ms + 30 * 24 * 3600 * 1000);
    let limit = params.limit.min(500) as usize;

    // 1. One-off (non-recurring) events in range.
    let one_off = state
        .storage
        .list_calendar_events_in_range(from_ms, to_ms, limit as u32)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // 2. All recurring master events (expansion is time-windowed in expand_occurrences).
    let masters = state
        .storage
        .list_recurring_master_events()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // 3. Exception/override records in range (parent_id IS NOT NULL).
    let exceptions = state
        .storage
        .list_calendar_exceptions_in_range(from_ms, to_ms)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // Index exception start times by parent_id for O(1) suppression lookup.
    let mut exc_by_parent: HashMap<String, HashSet<u64>> = HashMap::new();
    for exc in &exceptions {
        if let Some(pid) = &exc.parent_id {
            exc_by_parent.entry(pid.clone()).or_default().insert(exc.start_ms);
        }
    }

    let mut all_events: Vec<EventResponse> = Vec::new();

    // Add one-off events.
    for rec in one_off {
        all_events.push(EventResponse::try_from(rec)?);
    }

    // Expand each recurring master into individual occurrences.
    for master in &masters {
        let suppressed = exc_by_parent.get(&master.id);
        let occ_starts = expand_occurrences(master, from_ms as i64, to_ms as i64);
        let duration_ms = master.end_ms.saturating_sub(master.start_ms);
        let attendees: Vec<String> =
            serde_json::from_str(&master.attendees_json).unwrap_or_default();
        let recurrence: Option<serde_json::Value> = master
            .recurrence_json
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok());

        for start_i64 in occ_starts {
            if start_i64 < 0 {
                continue;
            }
            let start = start_i64 as u64;
            // Skip if an exception record overrides this occurrence.
            if suppressed.map(|s| s.contains(&start)).unwrap_or(false) {
                continue;
            }
            all_events.push(EventResponse {
                id: format!("{}-{}", master.id, start),
                message_id: master.message_id.clone(),
                organizer: master.organizer.clone(),
                title: master.title.clone(),
                description: master.description.clone(),
                start,
                end: start + duration_ms,
                tz: master.tz.clone(),
                location: master.location.clone(),
                attendees: attendees.clone(),
                recurrence: recurrence.clone(),
                color: master.color.clone(),
                created_at: master.created_at.clone(),
            });
        }
    }

    // Include exception/override records themselves (the override data).
    for exc in exceptions {
        all_events.push(EventResponse::try_from(exc)?);
    }

    // Sort by start time, then apply the client limit.
    all_events.sort_unstable_by_key(|e| e.start);
    all_events.truncate(limit);

    Ok(Json(all_events))
}

/// `POST /api/v1/calendar/events` — create an event and send to attendees.
async fn create_event(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateEventRequest>,
) -> Result<Json<EventActionResponse>, ApiError> {
    // Validate
    if req.title.is_empty() {
        return Err(ApiError::BadRequest("title cannot be empty".into()));
    }
    if req.start >= req.end {
        return Err(ApiError::BadRequest("start must be before end".into()));
    }
    if req.attendees.is_empty() {
        return Err(ApiError::BadRequest("at least one attendee required".into()));
    }
    if req.attendees.len() > 100 {
        return Err(ApiError::BadRequest("too many attendees (max 100)".into()));
    }

    let event_id = Uuid::new_v4().to_string();
    let organizer = auth.node_id.clone();

    // Parse attendee node IDs
    let peer_ids: Vec<NodeId> = req
        .attendees
        .iter()
        .map(|a| {
            NodeId::from_hex(a)
                .map_err(|e| ApiError::BadRequest(format!("invalid attendee node ID '{a}': {e}")))
        })
        .collect::<Result<_, _>>()?;

    // Build wire recurrence
    let wire_rrule = req.recurrence.as_ref().map(|r| WireRRule {
        freq: r.freq.clone(),
        interval: r.interval,
        until: r.until,
        count: r.count,
        byday: r.byday.clone(),
    });

    let attendees_json = serde_json::to_string(&req.attendees)
        .map_err(|e| ApiError::Internal(format!("attendees serialization: {e}")))?;
    let recurrence_json = wire_rrule
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| ApiError::Internal(format!("recurrence serialization: {e}")))?;

    // Store event locally first
    let record = CalendarEventRecord {
        id: event_id.clone(),
        message_id: None,
        organizer: organizer.clone(),
        title: req.title.clone(),
        description: req.description.clone(),
        start_ms: req.start,
        end_ms: req.end,
        tz: req.tz.clone(),
        location: req.location.clone(),
        attendees_json: attendees_json.clone(),
        recurrence_json: recurrence_json.clone(),
        color: req.color.clone(),
        created_at: String::new(), // set by DB default
        parent_id: None,
    };
    state
        .storage
        .store_calendar_event(&record)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // Send to each attendee
    let mut delivered_to = Vec::new();
    let mut queued_for = Vec::new();
    let mut total_msat: u64 = 0;
    let mut last_message_id: Option<String> = None;

    for peer_id in &peer_ids {
        let payload = CalendarEventPayload {
            event_id: event_id.clone(),
            title: req.title.clone(),
            description: req.description.clone(),
            start_ms: req.start,
            end_ms: req.end,
            tz: req.tz.clone(),
            location: req.location.clone(),
            organizer: organizer.clone(),
            attendees: req.attendees.clone(),
            recurrence: wire_rrule.clone(),
            color: req.color.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ApiError::Internal(format!("payload serialization: {e}")))?;

        let ratchet_msg = match state.session_manager.encrypt(peer_id, &payload_bytes).await {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(
                    peer = %peer_id,
                    error = %e,
                    "no E2EE session for attendee, skipping"
                );
                queued_for.push(peer_id.to_hex());
                continue;
            }
        };
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        let price_msat = state
            .pricing
            .get_price_msat(KIND_CALENDAR_EVENT)
            .await
            .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;

        let (payment_hash, preimage, amount_msat) =
            create_payment_proof(&state, price_msat, peer_id).await?;
        let proof = konsensus_core::PaymentProof::new(payment_hash, preimage, amount_msat);

        let sender = *state.identity.node_id();
        let recipient = Recipient::Node(*peer_id);
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            KIND_CALENDAR_EVENT,
            sender,
            recipient,
            ciphertext,
            proof,
        )
        .build();
        let sig = state.identity.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

        state
            .storage
            .store_message(&envelope)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        let msg_id_hex = envelope.id.to_hex();

        if state.transport.is_connected(peer_id).await {
            if let Err(e) = state.transport.send(peer_id, &envelope).await {
                tracing::warn!(peer = %peer_id, error = %e, "calendar event delivery failed, queuing");
                let _ = state.storage.queue_pending_delivery(&envelope.id, peer_id).await;
                queued_for.push(peer_id.to_hex());
            } else {
                delivered_to.push(peer_id.to_hex());
            }
        } else {
            let _ = state.storage.queue_pending_delivery(&envelope.id, peer_id).await;
            queued_for.push(peer_id.to_hex());
        }

        total_msat = total_msat.saturating_add(amount_msat);
        last_message_id = Some(msg_id_hex);
    }

    state.audit_log.record(
        events::MESSAGE_SENT,
        &organizer,
        Some(serde_json::json!({
            "kind": KIND_CALENDAR_EVENT,
            "event_id": event_id,
            "title": req.title,
            "delivered_to": delivered_to,
            "queued_for": queued_for,
            "amount_msat": total_msat,
        })),
    );

    Ok(Json(EventActionResponse {
        event_id,
        message_id: last_message_id,
        delivered_to,
        queued_for,
        amount_msat: total_msat,
    }))
}

/// `PUT /api/v1/calendar/events/:id` — update an event and notify attendees.
async fn update_event(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
    Json(req): Json<UpdateEventRequest>,
) -> Result<Json<EventActionResponse>, ApiError> {
    let existing = state
        .storage
        .get_calendar_event(&event_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("event {event_id} not found")))?;

    if existing.organizer != auth.node_id {
        return Err(ApiError::Unauthorized("only the organizer can update an event".into()));
    }

    // Apply updates
    let title = req.title.unwrap_or(existing.title.clone());
    let description = req.description.or(existing.description.clone());
    let start_ms = req.start.unwrap_or(existing.start_ms);
    let end_ms = req.end.unwrap_or(existing.end_ms);
    let tz = req.tz.unwrap_or(existing.tz.clone());
    let location = req.location.or(existing.location.clone());
    let color = req.color.or(existing.color.clone());

    if start_ms >= end_ms {
        return Err(ApiError::BadRequest("start must be before end".into()));
    }

    let wire_rrule = req.recurrence.as_ref().map(|r| WireRRule {
        freq: r.freq.clone(),
        interval: r.interval,
        until: r.until,
        count: r.count,
        byday: r.byday.clone(),
    });
    let recurrence_json = wire_rrule
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| ApiError::Internal(format!("recurrence serialization: {e}")))?
        .or(existing.recurrence_json.clone());

    let updated = CalendarEventRecord {
        id: existing.id.clone(),
        message_id: existing.message_id.clone(),
        organizer: existing.organizer.clone(),
        title: title.clone(),
        description: description.clone(),
        start_ms,
        end_ms,
        tz: tz.clone(),
        location: location.clone(),
        attendees_json: existing.attendees_json.clone(),
        recurrence_json,
        color: color.clone(),
        created_at: existing.created_at.clone(),
        parent_id: existing.parent_id.clone(),
    };
    state
        .storage
        .store_calendar_event(&updated)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // Parse attendees and send update
    let attendees: Vec<String> = serde_json::from_str(&existing.attendees_json)
        .map_err(|e| ApiError::Internal(format!("attendees deserialization: {e}")))?;
    let peer_ids: Vec<NodeId> = attendees
        .iter()
        .filter_map(|a| NodeId::from_hex(a).ok())
        .collect();

    let mut delivered_to = Vec::new();
    let mut queued_for = Vec::new();
    let mut total_msat: u64 = 0;
    let mut last_message_id: Option<String> = None;

    for peer_id in &peer_ids {
        let payload = CalendarEventPayload {
            event_id: event_id.clone(),
            title: title.clone(),
            description: description.clone(),
            start_ms,
            end_ms,
            tz: tz.clone(),
            location: location.clone(),
            organizer: existing.organizer.clone(),
            attendees: attendees.clone(),
            recurrence: wire_rrule.clone(),
            color: color.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ApiError::Internal(format!("payload serialization: {e}")))?;

        let ratchet_msg = match state.session_manager.encrypt(peer_id, &payload_bytes).await {
            Ok(msg) => msg,
            Err(_) => {
                queued_for.push(peer_id.to_hex());
                continue;
            }
        };
        let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

        let price_msat = state
            .pricing
            .get_price_msat(KIND_CALENDAR_UPDATE)
            .await
            .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;
        let (payment_hash, preimage, amount_msat) =
            create_payment_proof(&state, price_msat, peer_id).await?;
        let proof = konsensus_core::PaymentProof::new(payment_hash, preimage, amount_msat);

        let sender = *state.identity.node_id();
        let recipient = Recipient::Node(*peer_id);
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            KIND_CALENDAR_UPDATE,
            sender,
            recipient,
            ciphertext,
            proof,
        )
        .build();
        let sig = state.identity.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

        state
            .storage
            .store_message(&envelope)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        let msg_id_hex = envelope.id.to_hex();

        if state.transport.is_connected(peer_id).await {
            if let Err(e) = state.transport.send(peer_id, &envelope).await {
                tracing::warn!(peer = %peer_id, error = %e, "update delivery failed, queuing");
                let _ = state.storage.queue_pending_delivery(&envelope.id, peer_id).await;
                queued_for.push(peer_id.to_hex());
            } else {
                delivered_to.push(peer_id.to_hex());
            }
        } else {
            let _ = state.storage.queue_pending_delivery(&envelope.id, peer_id).await;
            queued_for.push(peer_id.to_hex());
        }

        total_msat = total_msat.saturating_add(amount_msat);
        last_message_id = Some(msg_id_hex);
    }

    Ok(Json(EventActionResponse {
        event_id,
        message_id: last_message_id,
        delivered_to,
        queued_for,
        amount_msat: total_msat,
    }))
}

/// `DELETE /api/v1/calendar/events/:id` — delete a local event record.
async fn delete_event(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let existing = state
        .storage
        .get_calendar_event(&event_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("event {event_id} not found")))?;

    if existing.organizer != auth.node_id {
        return Err(ApiError::Unauthorized("only the organizer can delete an event".into()));
    }

    let deleted = state
        .storage
        .delete_calendar_event(&event_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// `POST /api/v1/calendar/events/:id/rsvp` — RSVP to an event.
async fn create_rsvp(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
    Json(req): Json<CreateRsvpRequest>,
) -> Result<Json<RsvpActionResponse>, ApiError> {
    // Validate response string
    let response_str = req.response.to_lowercase();
    if !["accepted", "declined", "tentative"].contains(&response_str.as_str()) {
        return Err(ApiError::BadRequest(
            "response must be 'accepted', 'declined', or 'tentative'".into(),
        ));
    }

    let organizer_id = NodeId::from_hex(&req.organizer)
        .map_err(|e| ApiError::BadRequest(format!("invalid organizer node ID: {e}")))?;

    // Build RSVP payload
    let rsvp_response = match response_str.as_str() {
        "accepted" => RsvpResponse::Accepted,
        "declined" => RsvpResponse::Declined,
        _ => RsvpResponse::Tentative,
    };
    let payload = RsvpPayload {
        event_id: event_id.clone(),
        response: rsvp_response,
        comment: req.comment.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ApiError::Internal(format!("payload serialization: {e}")))?;

    // E2EE encrypt
    let ratchet_msg = state
        .session_manager
        .encrypt(&organizer_id, &payload_bytes)
        .await
        .map_err(|e| {
            ApiError::BadRequest(format!(
                "E2EE encryption failed (session may not be established): {e}"
            ))
        })?;
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    let price_msat = state
        .pricing
        .get_price_msat(KIND_RSVP)
        .await
        .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;
    let (payment_hash, preimage, amount_msat) =
        create_payment_proof(&state, price_msat, &organizer_id).await?;
    let proof = konsensus_core::PaymentProof::new(payment_hash, preimage, amount_msat);

    let sender = *state.identity.node_id();
    let recipient = Recipient::Node(organizer_id);
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        KIND_RSVP,
        sender,
        recipient,
        ciphertext,
        proof,
    )
    .build();
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    state
        .storage
        .store_message(&envelope)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let msg_id_hex = envelope.id.to_hex();

    // Store RSVP locally
    let rsvp_record = RsvpRecord {
        id: Uuid::new_v4().to_string(),
        event_id: event_id.clone(),
        responder: auth.node_id.clone(),
        response: response_str.clone(),
        comment: req.comment.clone(),
        created_at: String::new(),
    };
    // Best effort — the event may not be stored locally if this node is an attendee
    let _ = state.storage.store_rsvp(&rsvp_record).await;

    let delivered = if state.transport.is_connected(&organizer_id).await {
        match state.transport.send(&organizer_id, &envelope).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(peer = %organizer_id, error = %e, "RSVP delivery failed, queuing");
                let _ = state
                    .storage
                    .queue_pending_delivery(&envelope.id, &organizer_id)
                    .await;
                false
            }
        }
    } else {
        let _ = state
            .storage
            .queue_pending_delivery(&envelope.id, &organizer_id)
            .await;
        false
    };

    state.audit_log.record(
        events::MESSAGE_SENT,
        &auth.node_id,
        Some(serde_json::json!({
            "kind": KIND_RSVP,
            "event_id": event_id,
            "response": response_str,
            "organizer": req.organizer,
            "delivered": delivered,
            "amount_msat": amount_msat,
        })),
    );

    Ok(Json(RsvpActionResponse {
        event_id,
        response: response_str,
        message_id: msg_id_hex,
        delivered,
        amount_msat,
    }))
}

/// Register calendar routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/calendar/events",
            get(list_events).post(create_event),
        )
        .route(
            "/api/v1/calendar/events/:id",
            put(update_event).delete(delete_event),
        )
        .route("/api/v1/calendar/events/:id/rsvp", post(create_rsvp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsvp_response_validation() {
        for valid in ["accepted", "declined", "tentative"] {
            assert!(["accepted", "declined", "tentative"].contains(&valid));
        }
        assert!(!["accepted", "declined", "tentative"].contains(&"maybe"));
    }

    fn make_recurring_record(start_ms: u64, freq: &str, count: u32) -> CalendarEventRecord {
        let rrule = serde_json::json!({
            "freq": freq,
            "interval": 1,
            "count": count,
        });
        CalendarEventRecord {
            id: "master-001".to_string(),
            message_id: None,
            organizer: "aabb".to_string(),
            title: "Recurring".to_string(),
            description: None,
            start_ms,
            end_ms: start_ms + 3_600_000,
            tz: "UTC".to_string(),
            location: None,
            attendees_json: r#"[]"#.to_string(),
            recurrence_json: Some(rrule.to_string()),
            color: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            parent_id: None,
        }
    }

    #[test]
    fn event_response_from_record() {
        let record = CalendarEventRecord {
            id: "evt-001".to_string(),
            message_id: None,
            organizer: "aabb".to_string(),
            title: "Test".to_string(),
            description: None,
            start_ms: 1_000,
            end_ms: 2_000,
            tz: "UTC".to_string(),
            location: None,
            attendees_json: r#"["ccdd"]"#.to_string(),
            recurrence_json: None,
            color: None,
            created_at: "2026-04-16T00:00:00.000Z".to_string(),
            parent_id: None,
        };
        let resp = EventResponse::try_from(record).unwrap();
        assert_eq!(resp.id, "evt-001");
        assert_eq!(resp.attendees, vec!["ccdd"]);
        assert_eq!(resp.start, 1_000);
    }

    #[test]
    fn expand_occurrences_daily_count_3() {
        // 2026-01-01 09:00 UTC in ms
        let start_ms: u64 = 1_735_722_000_000;
        let record = make_recurring_record(start_ms, "DAILY", 3);
        let to = (start_ms + 10 * 86_400_000) as i64;
        let starts = expand_occurrences(&record, start_ms as i64, to);
        assert_eq!(starts.len(), 3);
        assert_eq!(starts[0], start_ms as i64);
        assert_eq!(starts[1], (start_ms + 86_400_000) as i64);
        assert_eq!(starts[2], (start_ms + 2 * 86_400_000) as i64);
    }

    #[test]
    fn expand_occurrences_weekly_count_2() {
        let start_ms: u64 = 1_735_722_000_000;
        let record = make_recurring_record(start_ms, "WEEKLY", 2);
        let to = (start_ms + 20 * 86_400_000) as i64;
        let starts = expand_occurrences(&record, start_ms as i64, to);
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[1], (start_ms + 7 * 86_400_000) as i64);
    }

    #[test]
    fn expand_occurrences_no_recurrence_returns_empty() {
        let record = CalendarEventRecord {
            id: "evt".to_string(),
            message_id: None,
            organizer: "aa".to_string(),
            title: "One-off".to_string(),
            description: None,
            start_ms: 1_000_000,
            end_ms: 2_000_000,
            tz: "UTC".to_string(),
            location: None,
            attendees_json: r#"[]"#.to_string(),
            recurrence_json: None,
            color: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            parent_id: None,
        };
        let starts = expand_occurrences(&record, 0, i64::MAX / 2);
        assert!(starts.is_empty());
    }

    #[test]
    fn expand_occurrences_unknown_freq_returns_empty() {
        let rrule = serde_json::json!({"freq": "HOURLY", "interval": 1});
        let mut record = make_recurring_record(1_000_000, "DAILY", 1);
        record.recurrence_json = Some(rrule.to_string());
        let starts = expand_occurrences(&record, 0, i64::MAX / 2);
        assert!(starts.is_empty());
    }

    #[test]
    fn expand_occurrences_monthly_count_3() {
        let start_ms: u64 = 1_735_722_000_000;
        let record = make_recurring_record(start_ms, "MONTHLY", 3);
        let to = (start_ms + 120 * 86_400_000) as i64;
        let starts = expand_occurrences(&record, start_ms as i64, to);
        assert_eq!(starts.len(), 3);
        assert!(starts.windows(2).all(|w| w[1] > w[0]));
    }
}
