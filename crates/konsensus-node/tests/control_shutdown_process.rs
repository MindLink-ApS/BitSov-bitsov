#![cfg(unix)]

use konsensus_api::control::{self, ControlRequest, ControlResponse};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn node_shutdown_waits_for_the_control_operation_response() {
    let dir = tempfile::tempdir().unwrap();
    let init = std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["init", "--non-interactive", "--tier", "light", "--dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(init.status.success());
    let config = dir.path().join("konsensus.toml");
    let mut cfg: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
    let api_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    cfg["api"]["listen_addr"] = api_port.local_addr().unwrap().to_string().into();
    cfg["network"]["listen_addr"] = peer_port.local_addr().unwrap().to_string().into();
    drop((api_port, peer_port));
    cfg["lightning"]["backend"] = "mock".into();
    cfg["chain"]["backend"] = "mock".into();
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["start", "--owner-control", "--config"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(log.reopen().unwrap())
        .stderr(log.reopen().unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let socket = dir.path().join(control::SOCKET_FILE);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if control::send(&socket, &ControlRequest::Status)
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "node exited before serving control requests: {}",
                std::fs::read_to_string(log.path()).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut control = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let request = serde_json::json!({"op":"add-peer", "node_id":"ab".repeat(32), "addr":listener.local_addr().unwrap().to_string(), "label":null});
    control
        .write_all(format!("{request}\n").as_bytes())
        .await
        .unwrap();
    // Holding this connection open parks the initial transport handshake.
    let (_peer, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    // SAFETY: this process owns the still-running child identified by this pid.
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
        0
    );
    let mut lines = BufReader::new(control).lines();
    let line = tokio::time::timeout(Duration::from_secs(8), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("shutdown must return the operation outcome before process exit");
    assert!(
        matches!(serde_json::from_str::<ControlResponse>(&line).unwrap(), ControlResponse::Error { message } if message.starts_with("node_stopping:") && message.contains("outcome is unknown"))
    );
    assert!(lines.next_line().await.unwrap().is_none());
    let exit = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(exit.success());
}
