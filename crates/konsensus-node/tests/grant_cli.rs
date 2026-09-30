//! `konsensus grant` is one step: it prints the terms, reads the owner code
//! the node showed on its own terminal, and sends exactly that. No yes/no
//! question and no pasted console line in between.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use konsensus_api::control::{ControlRequest, ControlResponse};
use konsensus_api::spend_budget::GrantTerms;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Serve the fake node: answer each request with `reply(request)`, and return
/// every request seen once the CLI exits.
async fn grant(
    stdin: &str,
    reply: impl Fn(&ControlRequest) -> ControlResponse + Send + 'static,
) -> (std::process::Output, Vec<ControlRequest>) {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Ok(Ok((stream, _))) =
            tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
        {
            let (reader, mut writer) = stream.into_split();
            let line = BufReader::new(reader).lines().next_line().await.unwrap().unwrap();
            let request: ControlRequest = serde_json::from_str(&line).unwrap();
            let response = reply(&request);
            seen.push(request);
            let mut bytes = serde_json::to_vec(&response).unwrap();
            bytes.push(b'\n');
            writer.write_all(&bytes).await.unwrap();
        }
        seen
    });
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["grant", "--op", "ab12", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    (output, server.await.unwrap())
}

fn described(request: &ControlRequest) -> ControlResponse {
    match request {
        ControlRequest::Describe { .. } => ControlResponse::Describe {
            summary: "SPEND BUDGET REQUEST\n  operation:   ab12".into(),
            confirmation_label: "GRANT spend TO ab12".into(),
            proposed_terms: Some(GrantTerms::new(2_000_000)),
            front_door: false,
        },
        _ => ControlResponse::Ok { detail: "granted spend to client c1".into() },
    }
}

#[tokio::test]
async fn one_step_grant_sends_the_typed_code_after_the_terms() {
    let (output, seen) = grant("k7qm-3xwd\n", described).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", String::from_utf8_lossy(&output.stderr));
    let terms_at = stdout.find("YOU ARE GRANTING").expect("terms printed");
    let ask_at = stdout.find("type the approval code").expect("code asked for");
    assert!(terms_at < ask_at, "the terms come before the question: {stdout}");
    assert!(!stdout.contains("[y/N]"), "{stdout}");
    assert!(stdout.contains("granted spend"), "{stdout}");
    match &seen[..] {
        [ControlRequest::Describe { op_id }, ControlRequest::Grant { op_id: granted, confirmation, terms }] => {
            assert_eq!((op_id.as_str(), granted.as_str()), ("ab12", "ab12"));
            // Sent as typed; the node normalizes and compares.
            assert_eq!(confirmation, "k7qm-3xwd");
            assert_eq!(terms.budget_msat, 2_000_000);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_empty_line_cancels_and_sends_nothing() {
    let (output, seen) = grant("\n", described).await;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("not granted"));
    assert!(
        matches!(&seen[..], [ControlRequest::Describe { .. }]),
        "no grant may be sent: {seen:?}"
    );
}

#[tokio::test]
async fn a_lost_request_fails_before_asking_for_a_code() {
    let (output, seen) = grant("K7QM-3XWD\n", |_| ControlResponse::Error {
        message: "this request can no longer be approved: the node restarted. Ask again from the app".into(),
    })
    .await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Ask again"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("type the approval code"));
    assert_eq!(seen.len(), 1);
}
