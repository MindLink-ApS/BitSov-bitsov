#[path = "../src/tests/log_capture.rs"]
mod log_capture;

fn probe() {
    tracing::warn!("interest probe");
}

#[test]
fn first_callsite_hit_without_a_subscriber_preserves_scoped_capture() {
    let (logs, _guard) = log_capture::capture_logs();
    std::thread::spawn(probe).join().unwrap();
    probe();
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("interest probe"), "captured output: {text}");
    assert_eq!(text.matches("interest probe").count(), 1, "{text}");

    drop(_guard);
    let global_logs = log_capture::LogBuf::default();
    let global = tracing_subscriber::fmt()
        .with_writer(global_logs.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(global).expect("global capture remains available");
    probe();
    let text = String::from_utf8(global_logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("interest probe"), "global output: {text}");
}
