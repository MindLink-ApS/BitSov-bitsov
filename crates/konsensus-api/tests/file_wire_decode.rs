use konsensus_api::handlers::files::FilePayload;
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

#[test]
fn honest_maximum_file_data_preserves_the_existing_upload_budget() {
    let data = "A".repeat(4_194_304usize.div_ceil(3) * 4);
    let payload = FilePayload {
        filename: "photo.bin".into(),
        mime_type: "application/octet-stream".into(),
        size_bytes: 4_194_304,
        blake3_hash: "00".repeat(32),
        data_b64: data.clone(),
    };
    let json = serde_json::to_vec(&payload).unwrap();
    let decoded = FilePayload::from_wire_bytes(&json).unwrap();
    assert_eq!(decoded.data_b64, data);
    assert_eq!(decoded.filename, "photo.bin");
}

#[test]
fn file_exception_does_not_admit_oversize_wrong_types_or_unknown_keys() {
    let token = format!(r"\n{}", "x".repeat(393_217));
    for json in [
        format!(r#"{{"size_bytes":"{token}"}}"#),
        format!(r#"{{"{token}":0}}"#),
        format!(r#"{{"data_b64":{{"data_b64":"{token}"}}}}"#),
    ] {
        TOTAL.set(0);
        LARGEST.set(Some(0));
        let result = FilePayload::from_wire_bytes(json.as_bytes());
        let largest = LARGEST.replace(None).unwrap();
        let total = TOTAL.get();
        assert_eq!(result.unwrap_err().to_string(), "invalid wire JSON");
        assert!(
            largest <= 4096 && total <= 16384,
            "largest={largest}, total={total}"
        );
    }
}

#[test]
fn file_exception_rejects_nested_unknown_key_lookalike() {
    // All required fields are valid, so removing the depth-one restriction
    // would let serde ignore the nested data_b64 and accept the whole payload.
    let json = format!(
        r#"{{"x":{{"data_b64":"{}"}},"filename":"photo.bin","mime_type":"application/octet-stream","size_bytes":0,"blake3_hash":"{}","data_b64":""}}"#,
        "A".repeat(5_000_000),
        "00".repeat(32),
    );
    TOTAL.set(0);
    LARGEST.set(Some(0));
    let result = FilePayload::from_wire_bytes(json.as_bytes());
    let largest = LARGEST.replace(None).unwrap();
    let total = TOTAL.get();
    assert_eq!(result.unwrap_err().to_string(), "invalid wire JSON");
    assert!(
        largest <= 4096 && total <= 16384,
        "largest={largest}, total={total}"
    );
}
