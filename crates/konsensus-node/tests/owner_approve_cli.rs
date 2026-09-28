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
            .map(str::to_owned)
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
