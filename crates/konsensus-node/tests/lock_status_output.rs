#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;

#[test]
fn lock_status_round_trips_json_without_terminal_formatting() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let status = json!({
        "state": "locked",
        "label\u{202e}": "text\u{0085}\u{009b}\u{061c}\u{200b}\u{2028}\u{202e}\u{2066}\u{feff}\u{1b}\n\t 🦀",
        "literal": "\\u{202e}",
        "nested": [{"ok": true, "count": 7}]
    });
    let reply = json!({"result": "lock-status", "status": status});
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "CLI did not connect");
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap(),
            json!({"op": "lock-status"})
        );
        writeln!(stream, "{reply}").unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .arg("lock-status")
        .arg("--config")
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), status);
    assert_eq!(text.lines().count(), 1);
    for c in [
        '\u{0085}', '\u{009b}', '\u{061c}', '\u{200b}', '\u{2028}', '\u{202e}', '\u{2066}',
        '\u{feff}', '\u{1b}',
    ] {
        assert!(!text.contains(c), "unescaped terminal formatting: {c:?}");
    }
}

#[test]
fn interrupted_control_response_keeps_its_unknown_outcome_wording() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "CLI did not connect");
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        writeln!(stream, "{}", json!({"result":"error", "message":"node_stopping: operation outcome is unknown; check status after restart"})).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .arg("lock-status")
        .arg("--config")
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("outcome is unknown") && error.contains("check status"),
        "{error}"
    );
    assert!(
        !error.contains("refused:"),
        "an interrupted operation is not a refusal: {error}"
    );
}
