//! `konsensus device approve` signs the described tuple with the owner-approval
//! key it derives from the node's own recovery phrase, and refuses to sign for
//! a node that is not that identity.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use konsensus_api::control::{ControlRequest, ControlResponse, DeviceApprovalTuple};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const DEVICE: &str = "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn approve(dir: &std::path::Path, node: String) -> (std::process::Output, Vec<ControlRequest>) {
    approve_with(dir, node, DEVICE).await
}

async fn approve_with(dir: &std::path::Path, node: String, device: &'static str) -> (std::process::Output, Vec<ControlRequest>) {
    let listener = tokio::net::UnixListener::bind(dir.join("control.sock")).unwrap();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Ok(Ok((stream, _))) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await {
            let (reader, mut writer) = stream.into_split();
            let line = BufReader::new(reader).lines().next_line().await.unwrap().unwrap();
            let request: ControlRequest = serde_json::from_str(&line).unwrap();
            let response = match &request {
                ControlRequest::Describe { .. } => ControlResponse::Describe {
                    summary: "DEVICE KEY REGISTRATION".into(),
                    confirmation_label: "REGISTER DEVICE k TO op1".into(),
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
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
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

fn init() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["init", "--dir"])
        .arg(dir.path())
        .args(["--non-interactive", "--tier", "light"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let mnemonic = std::fs::read_to_string(dir.path().join("mnemonic.txt")).unwrap();
    (dir, mnemonic.trim().to_string())
}

#[tokio::test]
async fn the_owner_key_signs_the_described_tuple_for_its_own_node() {
    let (dir, mnemonic) = init();
    let id = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let fp = konsensus_api::pairing::identity_fingerprint(&id.node_id().to_hex());
    let (out, seen) = approve(dir.path(), fp.clone()).await;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let ControlRequest::ApproveDeviceKey { confirmation, owner_signature, .. } = &seen[1] else {
        panic!("{seen:?}")
    };
    assert_eq!(confirmation, "K7QM-3XWD");
    // The fingerprint the owner compares is computed by the CLI from the signed bytes.
    let expected = konsensus_api::pairing::device::key_fingerprint(&konsensus_api::pairing::device::key_id_for(&hex::decode(DEVICE).unwrap()));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("device fingerprint:  {expected}")), "{stdout}");
    let message = konsensus_api::pairing::device::owner_approval_message(&fp, &"11".repeat(32), 3, DEVICE);
    let sig = ed25519_dalek::Signature::from_slice(&hex::decode(owner_signature).unwrap()).unwrap();
    // Verifies under the node's owner-approval public key, not its identity key.
    assert!(id.owner_approval_public().verify_strict(message.as_bytes(), &sig).is_ok());
    assert!(id.ed25519_verifying_key().verify_strict(message.as_bytes(), &sig).is_err());
}

#[tokio::test]
async fn it_refuses_to_sign_for_another_node() {
    let (dir, _) = init();
    let (out, seen) = approve(dir.path(), "0".repeat(32)).await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing was signed"));
    assert!(seen.iter().all(|r| !matches!(r, ControlRequest::ApproveDeviceKey { .. })), "{seen:?}");
}

#[tokio::test]
async fn it_refuses_a_malformed_tuple_before_signing() {
    let (dir, mnemonic) = init();
    let id = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let fp = konsensus_api::pairing::identity_fingerprint(&id.node_id().to_hex());
    // Same fake node, but it now claims a device key that is not a P-256 point.
    let (out, seen) = approve_with(dir.path(), fp, "04zz").await;
    assert!(!out.status.success());
    assert!(seen.iter().all(|r| !matches!(r, ControlRequest::ApproveDeviceKey { .. })), "{seen:?}");
}
