//! Inbound calendar caps are enforced before allocation: the counting
//! allocator below records every allocation request made while a peer payload
//! is decoded. Assertions are on allocation counters and the typed error path,
//! never on timing.

use konsensus_core::payloads::calendar::{
    CalendarEventPayload, CalendarPayloadError, RsvpPayload, MAX_ATTENDEES, MAX_BYDAY,
    MAX_CALENDAR_PAYLOAD_BYTES, MAX_DESCRIPTION_BYTES, MAX_RECURRENCE_INSTANCES,
    MAX_RSVP_PAYLOAD_BYTES,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    let _ = COUNTING.try_with(|counting| {
        if counting.get() {
            CALLS.with(|c| c.set(c.get() + 1));
            TOTAL.with(|t| t.set(t.get() + size));
        }
    });
}
// SAFETY: all operations forward the original pointer/layout to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Run `f` and return `(result, allocation calls, bytes requested)`.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    CALLS.set(0);
    TOTAL.set(0);
    COUNTING.set(true);
    let out = f();
    COUNTING.set(false);
    (out, CALLS.get(), TOTAL.get())
}

fn event_json(description_len: usize, attendees: usize, recurrence: &str) -> Vec<u8> {
    let attendee = format!("\"{}\"", "ab".repeat(32));
    let list = std::iter::repeat_n(attendee.as_str(), attendees)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"event_id":"evt-1","title":"Standup","description":"{}","start_ms":1700000000000,"end_ms":1700003600000,"tz":"UTC","organizer":"{}","attendees":[{}],"recurrence":{}}}"#,
        "d".repeat(description_len),
        "cd".repeat(32),
        list,
        recurrence
    )
    .into_bytes()
}

/// A payload over the byte cap is refused by its length alone: zero
/// allocation calls, and the error names the cap.
#[test]
fn oversize_payload_is_refused_with_zero_allocations() {
    let bytes = event_json(MAX_CALENDAR_PAYLOAD_BYTES, 1, "null");
    assert!(bytes.len() > MAX_CALENDAR_PAYLOAD_BYTES);
    let (result, calls, total) = measured(|| CalendarEventPayload::decode(&bytes));
    assert_eq!(
        result,
        Err(CalendarPayloadError::TooLarge {
            actual: bytes.len(),
            max: MAX_CALENDAR_PAYLOAD_BYTES
        })
    );
    assert_eq!(
        (calls, total),
        (0, 0),
        "byte cap must be checked before any allocation"
    );

    let rsvp = format!(
        r#"{{"event_id":"evt-1","response":"accepted","comment":"{}"}}"#,
        "c".repeat(MAX_RSVP_PAYLOAD_BYTES)
    );
    let (result, calls, total) = measured(|| RsvpPayload::decode(rsvp.as_bytes()));
    assert_eq!(
        result,
        Err(CalendarPayloadError::TooLarge {
            actual: rsvp.len(),
            max: MAX_RSVP_PAYLOAD_BYTES
        })
    );
    assert_eq!((calls, total), (0, 0));
}

/// A field over its cap inside an in-cap document is refused before the field
/// is copied: the bytes requested stay far below the field's own size.
#[test]
fn oversize_field_is_refused_before_copy() {
    let bytes = event_json(MAX_DESCRIPTION_BYTES + 1, 1, "null");
    assert!(bytes.len() <= MAX_CALENDAR_PAYLOAD_BYTES);
    let (result, _calls, total) = measured(|| CalendarEventPayload::decode(&bytes));
    assert_eq!(
        result,
        Err(CalendarPayloadError::FieldTooLong {
            field: "description",
            max: MAX_DESCRIPTION_BYTES
        })
    );
    assert!(
        total < MAX_DESCRIPTION_BYTES / 2,
        "description must not be copied before its cap is checked (requested {total} bytes)"
    );
}

/// An attendee list over the count cap is refused at entry `cap + 1`; the
/// declared length never drives an allocation. The fixture is fifty times the
/// cap in short entries, so the allocation calls (one per copied entry) show
/// where the guard stopped: without it they would run into the thousands.
#[test]
fn oversize_attendee_list_is_refused_at_the_cap() {
    let entries = 50 * MAX_ATTENDEES;
    let list = std::iter::repeat_n("\"abcdefgh\"", entries)
        .collect::<Vec<_>>()
        .join(",");
    let bytes = format!(
        r#"{{"event_id":"evt-1","title":"Standup","start_ms":1700000000000,"end_ms":1700003600000,"tz":"UTC","organizer":"{}","attendees":[{}]}}"#,
        "cd".repeat(32),
        list
    )
    .into_bytes();
    assert!(bytes.len() <= MAX_CALENDAR_PAYLOAD_BYTES);
    let (result, calls, total) = measured(|| CalendarEventPayload::decode(&bytes));
    assert_eq!(
        result,
        Err(CalendarPayloadError::TooManyEntries {
            field: "attendees",
            max: MAX_ATTENDEES
        })
    );
    // At most one allocation per admitted entry plus Vec growth, the decoder's
    // scratch and the error message; the other 4900 entries were never copied.
    assert!(
        calls <= MAX_ATTENDEES + 32,
        "attendees past the cap were copied ({calls} allocation calls for {entries} entries)"
    );
    assert!(total < 16 * 1024, "requested {total} bytes");
}

/// A recurrence that would expand past the cap is refused at decode. Nothing
/// is expanded: the allocation footprint is that of the small payload itself,
/// orders of magnitude below what materialising the series would need.
#[test]
fn recurrence_past_cap_is_refused_without_expansion() {
    let rule = format!(
        r#"{{"freq":"WEEKLY","until":{},"byday":{}}}"#,
        1_700_000_000_000u64 + 400 * 7 * 86_400_000,
        serde_json::to_string(&vec!["MO"; MAX_BYDAY]).unwrap()
    );
    let bytes = event_json(0, 1, &rule);
    let (result, _calls, total) = measured(|| CalendarEventPayload::decode(&bytes));
    assert_eq!(
        result,
        Err(CalendarPayloadError::RecurrenceTooLarge {
            estimated: 402 * MAX_BYDAY as u64,
            max: MAX_RECURRENCE_INSTANCES
        })
    );
    // One expanded occurrence clones the whole event; 6400 of them would
    // dwarf this bound.
    assert!(
        total < 8 * bytes.len(),
        "requested {total} bytes for a {}-byte payload",
        bytes.len()
    );

    let rule = format!(
        r#"{{"freq":"DAILY","count":{}}}"#,
        MAX_RECURRENCE_INSTANCES + 1
    );
    let bytes = event_json(0, 1, &rule);
    let (result, _, _) = measured(|| CalendarEventPayload::decode(&bytes));
    assert!(matches!(
        result,
        Err(CalendarPayloadError::RecurrenceTooLarge { .. })
    ));
}

/// In-cap payloads still decode, including a bounded recurrence and the full
/// attendee cap.
#[test]
fn in_cap_payloads_decode() {
    let rule = format!(r#"{{"freq":"DAILY","count":{}}}"#, MAX_RECURRENCE_INSTANCES);
    let bytes = event_json(MAX_DESCRIPTION_BYTES, MAX_ATTENDEES, &rule);
    assert!(bytes.len() <= MAX_CALENDAR_PAYLOAD_BYTES);
    let payload = CalendarEventPayload::decode(&bytes).unwrap();
    assert_eq!(payload.attendees.len(), MAX_ATTENDEES);
    assert_eq!(
        payload.description.as_deref().map(str::len),
        Some(MAX_DESCRIPTION_BYTES)
    );
    assert_eq!(
        payload.recurrence.unwrap().count,
        Some(MAX_RECURRENCE_INSTANCES as u32)
    );

    let open_ended = event_json(10, 2, r#"{"freq":"WEEKLY","byday":["MO","WE"]}"#);
    assert!(CalendarEventPayload::decode(&open_ended).is_ok());

    let rsvp = br#"{"event_id":"evt-1","response":"declined","comment":"sorry"}"#;
    assert_eq!(
        RsvpPayload::decode(rsvp).unwrap().comment.as_deref(),
        Some("sorry")
    );
}
