//! Exercise the installed command boundary: summary before dispatch, exact wire
//! tuple, leading-zero codes, and a nonzero exit when the node refuses.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn run(args: &[&str], expected: Value, reply: Value, success: bool) {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(args)
        .arg("--config")
        .arg(dir.path().join("konsensus.toml"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    // The command must print and flush before any server response is available.
    let summary = tokio::time::timeout(Duration::from_secs(10), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(summary.starts_with("Approve "), "{summary}");
    for (field, value) in expected.as_object().unwrap() {
        if field == "op" || value.is_null() {
            continue;
        }
        let rendered = value
            .as_str()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| value.to_string());
        assert!(
            summary.contains(&rendered),
            "summary omitted {field}: {summary}"
        );
    }
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (reader, mut writer) = stream.into_split();
    let request = BufReader::new(reader)
        .lines()
        .next_line()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&request).unwrap(), expected);
    writer
        .write_all(format!("{reply}\n").as_bytes())
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    if !success {
        assert!(String::from_utf8_lossy(&result.stderr).contains("refused"));
    }
}

#[tokio::test]
async fn first_contact_cli_sends_exact_tuple_after_summary() {
    run(
        &[
            "approve",
            "first-contact",
            "--client",
            "client-1",
            "--op",
            "grant-1",
            "--to",
            "recipient",
            "--max-msat",
            "4000",
            "--contact-budget-msat",
            "8000",
        ],
        json!({"op":"approve-first-contact", "client_id":"client-1", "grant_op_id":"grant-1",
            "recipient":"recipient", "max_total_msat":4000, "contact_budget_msat":8000}),
        json!({"result":"ok", "detail":"approved"}),
        true,
    )
    .await;
}

#[tokio::test]
async fn gift_cli_keeps_leading_zero_code_and_reports_node_refusal() {
    run(&["approve", "gift", "--intro", "intro-1", "--newcomer", "newcomer-key", "--hash", "payment-hash",
        "--gift-msat", "20000", "--fee-max-msat", "1000", "--code", "012345"],
        json!({"op":"approve-gift", "intro_id":"intro-1", "newcomer":"newcomer-key",
            "payment_hash":"payment-hash", "gift_msat":20000, "fee_max_msat":1000, "code":"012345"}),
        json!({"result":"error", "message":"tuple mismatch"}), false).await;
}

#[tokio::test]
async fn first_contact_cli_escapes_summary_and_preserves_wire_strings() {
    run(
        &["approve", "first-contact", "--client", "client\"quoted", "--op", "grant\\path",
            "--to", "recipient\u{2028}next", "--max-msat", "4000"],
        json!({"op":"approve-first-contact", "client_id":"client\"quoted", "grant_op_id":"grant\\path",
            "recipient":"recipient\u{2028}next", "max_total_msat":4000, "contact_budget_msat":null}),
        json!({"result":"ok", "detail":"approved"}), true,
    ).await;
}

#[tokio::test]
async fn gift_cli_escapes_summary_and_preserves_wire_strings() {
    run(
        &["approve", "gift", "--intro", "intro\"quoted", "--newcomer", "key\\path", "--hash", "hash\u{2028}next",
            "--gift-msat", "20000", "--fee-max-msat", "1000", "--code", "012345"],
        json!({"op":"approve-gift", "intro_id":"intro\"quoted", "newcomer":"key\\path",
            "payment_hash":"hash\u{2028}next", "gift_msat":20000, "fee_max_msat":1000, "code":"012345"}),
        json!({"result":"ok", "detail":"approved"}), true,
    ).await;
}

#[test]
fn approval_cli_rejects_cr_lf_and_escape_before_summary_or_dispatch() {
    for command in ["first-contact", "gift"] {
        for injection in ["\r", "\n", "\u{1b}[2J"] {
            let value = format!("id{injection}forged");
            let args = if command == "first-contact" {
                vec![
                    "approve",
                    command,
                    "--client",
                    &value,
                    "--op",
                    "grant-1",
                    "--to",
                    "recipient",
                    "--max-msat",
                    "4000",
                ]
            } else {
                vec![
                    "approve",
                    command,
                    "--intro",
                    &value,
                    "--newcomer",
                    "key",
                    "--hash",
                    "hash",
                    "--gift-msat",
                    "20000",
                    "--fee-max-msat",
                    "1000",
                    "--code",
                    "012345",
                ]
            };
            let result = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
                .args(args)
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(2), "must fail during parsing");
            assert!(
                result.stdout.is_empty(),
                "must not print an approval summary"
            );
            assert!(!String::from_utf8_lossy(&result.stderr).contains("owner control socket"));
            assert!(
                !String::from_utf8_lossy(&result.stderr).contains(&value),
                "diagnostic must not echo injected controls: {:?}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}


#[test]
fn approval_cli_rejects_unicode_format_controls_in_every_field() {
    let commands = [
        vec!["approve", "first-contact", "--client", "client-1", "--op", "grant-1",
            "--to", "recipient", "--max-msat", "4000", "--config", "missing/konsensus.toml"],
        vec!["approve", "gift", "--intro", "intro-1", "--newcomer", "key", "--hash", "hash",
            "--gift-msat", "20000", "--fee-max-msat", "1000", "--code", "012345",
            "--config", "missing/konsensus.toml"],
    ];
    let controls: Vec<char> = ['\u{061c}', '\u{feff}'].into_iter()
        .chain('\u{200b}'..='\u{200f}')
        .chain('\u{202a}'..='\u{202e}')
        .chain('\u{2066}'..='\u{2069}')
        .collect();
    let mut failures = Vec::new();
    for command in commands {
        for index in (3..command.len()).step_by(2) {
            let flag = command[index - 1];
            if matches!(flag, "--max-msat" | "--gift-msat" | "--fee-max-msat") {
                continue;
            }
            for &control in &controls {
                let original = command[index];
                for position in [0, original.len() / 2, original.len()] {
                    let mut value = original.to_owned();
                    value.insert(position, control);
                    let mut args = command.clone();
                    args[index] = &value;
                    let result = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
                        .args(args).output().unwrap();
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    if result.status.code() != Some(2) || !result.stdout.is_empty()
                        || stderr.contains("owner control socket") || stderr.contains(control)
                    {
                        failures.push(format!("{} {flag} {value:?}: status {:?}, stdout {:?}, stderr {stderr:?}",
                            command[1], result.status.code(), String::from_utf8_lossy(&result.stdout)));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "unsafe arguments: {failures:#?}");
}

#[test]
fn approval_cli_escapes_config_path_in_connection_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("missing\"\\line\u{2028}next").join("konsensus.toml");
    for args in [
        vec!["approve", "first-contact", "--client", "client-1", "--op", "grant-1",
            "--to", "recipient", "--max-msat", "4000"],
        vec!["approve", "gift", "--intro", "intro-1", "--newcomer", "key", "--hash", "hash",
            "--gift-msat", "20000", "--fee-max-msat", "1000", "--code", "012345"],
    ] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(args).arg("--config").arg(&config).output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("owner control socket"), "{stderr:?}");
        assert!(!stderr.contains('\u{2028}'), "{stderr:?}");
        assert!(stderr.contains(r#"missing\"\\line\u{2028}next/control.sock"#), "{stderr:?}");
    }
}
