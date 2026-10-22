use konsensus_core::{payloads::content::PageResponse, wire_json};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct MeasuredAllocator;
thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
            TOTAL.with(|total| total.set(total.get() + size));
        }
    });
}
// SAFETY: all operations forward the original pointer/layout to System.
unsafe impl GlobalAlloc for MeasuredAllocator {
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
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn rejected(json: &str) {
    TOTAL.set(0);
    LARGEST.set(Some(0));
    let result = PageResponse::from_wire_bytes(json.as_bytes());
    let largest = LARGEST.replace(None).unwrap();
    let total = TOTAL.get();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid wire JSON");
    assert!(
        largest <= 4096 && total <= 16384,
        "largest={largest}, total={total}"
    );
}

#[test]
fn payload_exceptions_cannot_relax_keys_wrong_types_or_nested_fields() {
    let token = format!(r"\n{}", "x".repeat(393_217));
    for json in [
        format!(r#"{{"cache_seconds":"{token}"}}"#),
        format!(r#"{{"body":"ok","{token}":0}}"#),
        format!(r#"{{"body":0,"cache_seconds":"{token}"}}"#),
        format!(r#"{{"body":{{"body":"{token}"}}}}"#),
        format!(r#"{{"body":["{token}"]}}"#),
        format!(r#"{{"future":{{"body":"{token}"}}}}"#),
        format!(r#"{{"body":"{}"}}"#, "x".repeat(262_145)),
        format!(r#"{{"body":"{}"}}"#, r"\u0078".repeat(262_145)),
    ] {
        rejected(&json);
    }
}

#[test]
fn honest_maximum_page_body_accepts_plain_and_escaped_strings_and_keys() {
    for key in ["body", r"b\u006fdy"] {
        for token in ["x".repeat(262_144), r"\u0078".repeat(262_144)] {
            let json = format!(r#"{{"request_id":"r","status":"Ok","{key}":"{token}"}}"#);
            let page = PageResponse::from_wire_bytes(json.as_bytes()).unwrap();
            assert_eq!(page.body.len(), 262_144);
            assert!(page.body.bytes().all(|b| b == b'x'));
        }
    }
}

#[test]
fn shared_preflight_rejects_depth_and_unterminated_tokens_without_allocating() {
    for json in [
        format!("{}0{}", "[".repeat(129), "]".repeat(129)),
        format!("\"{}", "x".repeat(393_217)),
    ] {
        TOTAL.set(0);
        LARGEST.set(Some(0));
        let result = wire_json::from_str::<serde_json::Value>(&json);
        let largest = LARGEST.replace(None).unwrap();
        assert!(result.is_err());
        assert_eq!(largest, 0);
    }
}

#[test]
fn unterminated_large_body_is_rejected_before_serde_scratch() {
    for prefix in ["", r"\n", r"\u0078"] {
        let json = format!("{{\"body\":\"{prefix}{}\\n", "x".repeat(1024 * 1024));
        rejected(&json);
    }
}

#[test]
fn oversized_room_chat_never_falls_back_to_unbound_chat() {
    use konsensus_core::payloads::room::RoomChat;
    for field in ["future", "text"] {
        let json = format!(r#"{{"room":{{}},"{field}":"{}"}}"#, "x".repeat(393_217));
        assert!(
            RoomChat::parse(&json).is_err(),
            "room admission must fail closed"
        );
    }
    let json = format!(r#"{{"room":{{}},"{}":0}}"#, r"\u0078".repeat(65_537));
    assert!(RoomChat::parse(&json).is_err());
    assert!(RoomChat::parse(r#"{"ordinary":"chat"}"#).unwrap().is_none());
}
