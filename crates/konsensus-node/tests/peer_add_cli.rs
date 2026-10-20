//! Owner peer admission validates before connecting and requires explicit CLI consent.
#![cfg(unix)]
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const ID: &str = "abababababababababababababababababababababababababababababababab";

async fn run(
    args: &[&str],
    input: &str,
    config: Option<&str>,
    reply: Value,
) -> (std::process::Output, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("konsensus.toml");
    if let Some(config) = config {
        std::fs::write(&path, config).unwrap();
    }
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let requests = count.clone();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        loop {
            let stream = tokio::select! {
                accepted = listener.accept() => accepted.unwrap().0,
                _ = &mut stopped => break,
            };
            let (reader, mut writer) = stream.into_split();
            let line = BufReader::new(reader)
                .lines()
                .next_line()
                .await
                .unwrap()
                .unwrap();
            requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            seen.push(serde_json::from_str(&line).unwrap());
            writer
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .unwrap();
        }
        seen
    });
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["peer", "add", "--config"])
        .arg(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut prefix = Vec::new();
    // Observe the prompt while stdin is open; no request may precede Enter.
    if !args.contains(&"--yes") && !input.is_empty() {
        let stdout = child.stdout.as_mut().unwrap();
        let mut reader = BufReader::new(stdout);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut line = String::new();
                assert!(
                    reader.read_line(&mut line).await.unwrap() > 0,
                    "missing confirmation prompt"
                );
                prefix.extend_from_slice(line.as_bytes());
                if line.contains("Press Enter") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        // Keep any bytes already buffered so wait_with_output does not lose them.
        prefix.extend_from_slice(reader.buffer());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(child.try_wait().unwrap().is_none(), "must wait for Enter");
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no request before Enter"
        );
    }
    let _ = stdin.write_all(input.as_bytes()).await;
    drop(stdin);
    let mut output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    prefix.extend_from_slice(&output.stdout);
    output.stdout = prefix;
    let _ = stop.send(());
    (output, server.await.unwrap())
}

fn ok() -> Value {
    json!({"result":"ok", "detail":"added Dad — connected"})
}
fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn enter_prints_summary_then_sends_exactly_one_tuple() {
    let (output, seen) = run(
        &[
            "--node-id",
            ID,
            "--addr",
            "127.0.0.1:9735",
            "--label",
            "Dad",
        ],
        "\n",
        None,
        ok(),
    )
    .await;
    assert!(output.status.success(), "{}", text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Add contact",
        ID,
        "fingerprint:",
        "abababab",
        "127.0.0.1:9735",
        "Dad",
        "paid traffic",
        "Press Enter",
        "connected",
    ] {
        assert!(stdout.contains(expected), "{stdout}");
    }
    assert_eq!(
        seen,
        vec![json!({"op":"add-peer", "node_id":ID, "addr":"127.0.0.1:9735", "label":"Dad"})]
    );
}

#[tokio::test]
async fn yes_skips_prompt_and_warns_about_case_insensitive_config_collision() {
    let config = format!(
        "[identity]\nmnemonic_file = 'unused.txt'\n[network]\n[lightning]\nbackend = 'mock'\n[chain]\nbackend = 'mock'\n[storage]\nbackend = 'sqlite'\npath = 'unused.db'\n[[peers]]\nnode_id = '{}'\naddr = '127.0.0.1:9999'\n",
        ID.to_uppercase()
    );
    let (output, seen) = run(
        &["--node-id", ID, "--addr", "127.0.0.1:9735", "--yes"],
        "",
        Some(&config),
        ok(),
    )
    .await;
    assert!(output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains("Press Enter"));
    assert!(text(&output).contains("[[peers]]"));
    assert!(text(&output).contains("config entry wins at the next restart"));
    assert_eq!(seen.len(), 1);
}

#[tokio::test]
async fn invalid_inputs_never_connect() {
    for (id, addr, label) in [
        ("bad", "127.0.0.1:9735", "Dad".to_string()),
        (ID, "example.com:9735", "Dad".to_string()),
        (ID, "0.0.0.0:9735", "Dad".to_string()),
        (ID, "[::]:9735", "Dad".to_string()),
        (ID, "127.0.0.1:0", "Dad".to_string()),
        (ID, "224.0.0.1:9735", "Dad".to_string()),
        (ID, "[ff02::1]:9735", "Dad".to_string()),
        (ID, "127.0.0.1:9735", "a".repeat(257)),
        (ID, "127.0.0.1:9735", "é".repeat(129)),
        (ID, "127.0.0.1:9735", "Dad\nspoof".to_string()),
        (ID, "127.0.0.1:9735", "Dad\u{1b}[2J".to_string()),
        (ID, "127.0.0.1:9735", "Dad\u{202e}spoof".to_string()),
    ] {
        let (output, seen) = run(
            &["--node-id", id, "--addr", addr, "--label", &label, "--yes"],
            "",
            None,
            ok(),
        )
        .await;
        assert!(!output.status.success());
        assert!(seen.is_empty());
        assert!(
            !text(&output).contains("unrecognized subcommand"),
            "{}",
            text(&output)
        );
        if addr.starts_with("example") {
            assert!(text(&output).contains("IP address and port only"));
        }
    }
}

#[tokio::test]
async fn eof_does_not_consent() {
    let (output, seen) = run(
        &["--node-id", ID, "--addr", "127.0.0.1:9735"],
        "",
        None,
        ok(),
    )
    .await;
    assert!(!output.status.success());
    assert!(seen.is_empty());
    assert!(text(&output).contains("cancel"));
}

#[tokio::test]
async fn socket_error_is_failure_and_terminal_safe() {
    let (output, seen) = run(
        &["--node-id", ID, "--addr", "127.0.0.1:9735", "--yes"],
        "",
        None,
        json!({"result":"error", "message":"denied\u{1b}[2J"}),
    )
    .await;
    assert!(!output.status.success());
    assert_eq!(seen.len(), 1);
    assert!(text(&output).contains("denied\\u{1b}[2J"));
    assert!(!text(&output).contains('\u{1b}'));
}

#[test]
fn missing_socket_mentions_owner_control() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args([
            "peer",
            "add",
            "--node-id",
            ID,
            "--addr",
            "127.0.0.1:9735",
            "--yes",
            "--config",
        ])
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        text(&output).contains("--owner-control"),
        "{}",
        text(&output)
    );
}
