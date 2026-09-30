//! `konsensus device approve` against a fake (untrusted) control socket:
//! it fails closed unless the recovery phrase is encrypted, prints nothing the
//! socket wrote, and shows only terms it computed from the bytes it signs.
//! The signing itself (which needs a typed password) is unit-tested in
//! `cli/owner.rs` through an injected password source.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use konsensus_api::control::{ControlRequest, ControlResponse, DeviceApprovalTuple};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const DEVICE: &str = "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A hostile summary: a fake fingerprint, then ANSI "conceal" for what follows.
const HOSTILE_SUMMARY: &str = "device fingerprint:  AAAA-BBBB-CCCC-DDDD\x1b[8m";

async fn approve(dir: &std::path::Path, node: String, device: &'static str) -> (std::process::Output, Vec<ControlRequest>) {
    let listener = tokio::net::UnixListener::bind(dir.join("control.sock")).unwrap();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Ok(Ok((stream, _))) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await {
            let (reader, mut writer) = stream.into_split();
            let line = BufReader::new(reader).lines().next_line().await.unwrap().unwrap();
            let request: ControlRequest = serde_json::from_str(&line).unwrap();
            let response = match &request {
                ControlRequest::Describe { .. } => ControlResponse::Describe {
                    summary: HOSTILE_SUMMARY.into(),
                    confirmation_label: "REGISTER DEVICE k TO op1\x1b[2J".into(),
                    proposed_terms: None,
                    front_door: false,
                    device: Some(DeviceApprovalTuple {
                        node: node.clone(),
                        client_pubkey: "11".repeat(32),
                        epoch: 3,
                        device_public_key: device.into(),
                    }),
                },
                _ => ControlResponse::Ok { detail: "registered".into() },
            };
            seen.push(request);
            let mut bytes = serde_json::to_vec(&response).unwrap();
            bytes.push(b'\n');
            writer.write_all(&bytes).await.unwrap();
        }
        seen
    });
    let mut std_cmd = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"));
    detach(&mut std_cmd);
    let mut child = tokio::process::Command::from(std_cmd)
        .args(["device", "approve", "--op", "op1", "--config"])
        .arg(dir.join("konsensus.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"K7QM-3XWD\n").await.unwrap();
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await.unwrap().unwrap();
    (out, server.await.unwrap())
}

/// `konsensus init`, optionally with an encrypted recovery phrase.
fn init(encrypt: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"));
    cmd.args(["init", "--dir"]).arg(dir.path()).args(["--non-interactive", "--tier", "light"]);
    if encrypt {
        cmd.args(["--encrypt", "correct horse battery"]);
    }
    assert!(cmd.stdout(Stdio::null()).status().unwrap().success());
    dir
}

#[tokio::test]
async fn a_plaintext_recovery_phrase_is_refused_before_anything_is_asked() {
    let dir = init(false);
    let (out, seen) = approve(dir.path(), "0".repeat(32), DEVICE).await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not encrypted") && stderr.contains("Nothing was signed"), "{stderr}");
    assert!(seen.is_empty(), "the socket is not even asked: {seen:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("code>"));
}

#[tokio::test]
async fn a_leftover_plaintext_copy_is_refused_too() {
    let dir = init(true);
    std::fs::write(dir.path().join("mnemonic.txt"), "abandon ...").unwrap();
    let (out, seen) = approve(dir.path(), "0".repeat(32), DEVICE).await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("plaintext copy"));
    assert!(seen.is_empty());
}

#[tokio::test]
async fn socket_text_is_never_printed_and_the_terms_shown_are_computed_locally() {
    let dir = init(true);
    let (out, seen) = approve(dir.path(), "0".repeat(32), DEVICE).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Nothing the socket wrote reaches the terminal: no escape byte, no fake fingerprint.
    assert!(!out.stdout.contains(&0x1b) && !out.stderr.contains(&0x1b), "{stdout:?}");
    assert!(!stdout.contains("AAAA-BBBB-CCCC-DDDD"), "{stdout}");
    let expected = konsensus_api::pairing::device::key_fingerprint(
        &konsensus_api::pairing::device::key_id_for(&hex::decode(DEVICE).unwrap()),
    );
    assert!(stdout.contains(&format!("device fingerprint:  {expected}")), "{stdout}");
    assert!(stdout.contains("computed by this command"), "{stdout}");
    // With no terminal to type the password on, nothing is signed or sent.
    assert!(!out.status.success());
    assert!(seen.iter().all(|r| !matches!(r, ControlRequest::ApproveDeviceKey { .. })), "{seen:?}");
}

#[tokio::test]
async fn a_malformed_tuple_is_refused_before_signing() {
    let dir = init(true);
    let (out, seen) = approve(dir.path(), "0".repeat(32), "04zz").await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("malformed device key"));
    assert!(seen.iter().all(|r| !matches!(r, ControlRequest::ApproveDeviceKey { .. })), "{seen:?}");
}

/// Run the command in a new session with no controlling terminal, so a
/// password prompt fails at once even when the tests run in a terminal.
fn detach(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and touches no Rust state; it runs
    // in the forked child before exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
