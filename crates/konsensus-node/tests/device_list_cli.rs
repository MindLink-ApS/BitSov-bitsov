//! Pending device expiry is shown as Unix seconds followed by readable UTC.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use konsensus_api::control::{ControlRequest, ControlResponse, PendingDeviceKeySummary};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn pending_devices_show_unix_expiry_then_utc() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let line = BufReader::new(reader)
            .lines()
            .next_line()
            .await
            .unwrap()
            .unwrap();
        let request: ControlRequest = serde_json::from_str(&line).unwrap();
        assert!(matches!(request, ControlRequest::Status));
        let response = ControlResponse::Status {
            enrollment: None,
            second_device_alerts: vec![],
            clients: vec![],
            pending_elevations: vec![],
            pending_replacements: vec![],
            grants: vec![],
            front_door_grants: vec![],
            device_keys: vec![],
            pending_device_keys: [false, true]
                .into_iter()
                .map(|lost| PendingDeviceKeySummary {
                    op_id: if lost { "cancelled" } else { "pending" }.into(),
                    fingerprint: "AAAA-BBBB".into(),
                    client_id: "client".into(),
                    client_name: "phone".into(),
                    name: "device".into(),
                    expires_at: 1_794_240_082,
                    lost,
                })
                .collect(),
            pending_owner_approvals: vec![],
        };
        let mut bytes = serde_json::to_vec(&response).unwrap();
        bytes.push(b'\n');
        writer.write_all(&bytes).await.unwrap();
    });
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["device", "list", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(20), async {
        let (output, served) = tokio::join!(child.wait_with_output(), server);
        served.unwrap();
        output.unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let rows: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("PENDING DEVICE KEY "))
        .collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    for row in rows {
        assert!(
            row.ends_with("expires_at=1794240082 (2026-11-09T16:01:22Z)"),
            "{row}"
        );
    }
    assert!(stdout.contains("approve with: konsensus device approve --op pending"));
    assert!(stdout.contains("cancelled by wrong codes; ask again from the app"));
}
