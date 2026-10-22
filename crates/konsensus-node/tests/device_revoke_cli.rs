//! Exercise the shipped CLI against a control socket: live rollout routing,
//! reviewable child keys, zero-owner protection, and typed confirmation.
#![cfg(unix)]
use konsensus_api::control::{ControlRequest as Q, ControlResponse as R};
use konsensus_api::pairing::console::{RevokeKey, RevokePlan};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn revoke(
    disk_enabled: bool,
    running_enabled: bool,
    owners: usize,
    input: &str,
    extra: &[&str],
) -> (std::process::Output, Vec<Q>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("konsensus.toml");
    std::fs::write(&path, format!(
        "[identity]\nmnemonic_file = 'unused.txt'\n[network]\n[lightning]\nbackend = 'mock'\n[chain]\nbackend = 'mock'\n[storage]\nbackend = 'sqlite'\npath = 'unused.db'\n[pairing]\nsecond_device_enrollment = {disk_enabled}\n"
    )).unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
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
            let request: Q = serde_json::from_str(&line).unwrap();
            let response = match &request {
                Q::Status => serde_json::from_value::<R>(serde_json::json!({
                    "result": "status",
                    "enrollment": running_enabled.then(|| serde_json::json!({"provisional": [], "words": {}})),
                    "clients": [], "pending_elevations": [], "pending_replacements": []
                })).unwrap(),
                Q::RevokeDevices { .. } => R::RevokePlan { plan: RevokePlan {
                    keys: vec![RevokeKey { key_id: "root-key".into(), client_id: "root-client".into(),
                        name: "Mac".into(), enrolled_by: "console".into() }],
                    descendants: vec![RevokeKey { key_id: "child-key".into(), client_id: "child-client".into(),
                        name: "Phone".into(), enrolled_by: "device:root-key".into() }],
                    pairings: vec![], owner_device_count: owners, confirmation: "reviewed-plan".into(),
                } },
                Q::RevokeDeviceKey { .. } => R::Ok { detail: "legacy revoked".into() },
                _ => panic!("unexpected request: {}", line),
            };
            seen.push(request);
            let mut bytes = serde_json::to_vec(&response).unwrap();
            bytes.push(b'\n');
            writer.write_all(&bytes).await.unwrap();
        }
        seen
    });
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["device", "revoke", "--key", "root-key", "--config"])
        .arg(path)
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A refusal may close stdin before the write reaches it.
    let _ = stdin.write_all(input.as_bytes()).await;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let _ = stop.send(());
    (output, server.await.unwrap())
}

#[tokio::test]
async fn live_flag_routes_key_revoke_and_cli_prints_children_before_confirmation() {
    let (out, seen) = revoke(false, true, 1, "revoke\n", &[]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let child = stdout
        .find("DESCENDANT child-key \"Phone\" enrolled_by=device:root-key")
        .expect("CLI must print child key and provenance");
    assert!(
        stdout.contains("Remove descendants with: konsensus device revoke --approved-by root-key")
    );
    assert!(child < stdout.find("Type revoke to confirm").unwrap());
    assert!(
        matches!(seen.as_slice(), [Q::Status, Q::RevokeDevices { confirmation: None, .. }, Q::RevokeDevices { confirmation: Some(digest), .. }] if digest == "reviewed-plan"),
        "unexpected request sequence ({} requests)",
        seen.len()
    );
}

#[tokio::test]
async fn disk_flag_cannot_force_v2_routing_when_running_process_has_it_off() {
    let (out, seen) = revoke(true, false, 1, "", &[]).await;
    assert!(out.status.success());
    assert!(
        matches!(seen.as_slice(), [Q::Status, Q::RevokeDeviceKey { key_id }] if key_id == "root-key"),
        "unexpected request sequence ({} requests)",
        seen.len()
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Type revoke"));
}

#[tokio::test]
async fn live_key_revoke_does_not_commit_without_typed_confirmation() {
    for input in ["\n", "yes\n"] {
        let (out, seen) = revoke(false, true, 1, input, &[]).await;
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("not revoked"));
        assert!(
            matches!(
                seen.as_slice(),
                [
                    Q::Status,
                    Q::RevokeDevices {
                        confirmation: None,
                        ..
                    }
                ]
            ),
            "unexpected request sequence ({} requests)",
            seen.len()
        );
    }
}

#[tokio::test]
async fn live_key_revoke_refuses_zero_owner_without_override() {
    let (out, seen) = revoke(false, true, 0, "revoke\n", &[]).await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("zero owner devices"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Type revoke"));
    assert!(
        matches!(
            seen.as_slice(),
            [
                Q::Status,
                Q::RevokeDevices {
                    confirmation: None,
                    ..
                }
            ]
        ),
        "unexpected request sequence ({} requests)",
        seen.len()
    );
}

#[tokio::test]
async fn zero_owner_override_still_requires_the_reviewed_confirmation() {
    let (out, seen) = revoke(false, true, 0, "revoke\n", &["--allow-zero-owner"]).await;
    assert!(out.status.success());
    assert!(
        matches!(seen.last(), Some(Q::RevokeDevices { options, confirmation: Some(digest) }) if options.allow_zero_owner && digest == "reviewed-plan")
    );
}
