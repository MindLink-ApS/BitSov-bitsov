//! Real owner socket + CLI + TCP transport + SQLite boot merge, with no config edit.
#![cfg(unix)]
use konsensus_core::NodeIdentity;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Node {
    dir: tempfile::TempDir,
    config: PathBuf,
    api: SocketAddr,
    peer: SocketAddr,
    identity: NodeIdentity,
    log: PathBuf,
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(["init", "--non-interactive", "--tier", "light", "--dir"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let config = dir.path().join("konsensus.toml");
        let mut cfg: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        let api = address();
        let peer = address();
        cfg["api"]["listen_addr"] = api.to_string().into();
        cfg["network"]["listen_addr"] = peer.to_string().into();
        cfg["lightning"]["backend"] = "mock".into();
        cfg["chain"]["backend"] = "mock".into();
        let phrase =
            std::fs::read_to_string(cfg["identity"]["mnemonic_file"].as_str().unwrap()).unwrap();
        let identity = NodeIdentity::from_mnemonic(phrase.trim(), "").unwrap();
        std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
        let log = dir.path().join("process.log");
        Self {
            dir,
            config,
            api,
            peer,
            identity,
            log,
        }
    }
    fn start(&self, owner_control: bool) -> Process {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        command.args(["start", "--config"]).arg(&self.config);
        if owner_control {
            command.arg("--owner-control");
        }
        Process(
            command
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        )
    }
    async fn ready(&self, process: &mut Process, http: &reqwest::Client, owner: bool) {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Ok(resp) = http
                .get(format!("http://{}/api/v1/health", self.api))
                .send()
                .await
            {
                if resp.status().is_success()
                    && (!owner || self.dir.path().join("control.sock").exists())
                {
                    return;
                }
            }
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "node exited: {}",
                self.logs()
            );
            assert!(Instant::now() < deadline, "node not ready: {}", self.logs());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }
    async fn token(&self, http: &reqwest::Client) -> String {
        let challenge: Value = http
            .get(format!("http://{}/api/v1/auth/challenge", self.api))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let signature = hex::encode(
            self.identity
                .sign(challenge["challenge"].as_str().unwrap().as_bytes())
                .to_bytes(),
        );
        let response: Value = http
            .post(format!("http://{}/api/v1/auth/token", self.api))
            .json(&json!({"challenge": challenge["challenge"], "signature": signature}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        response["token"].as_str().unwrap().into()
    }
    async fn get(&self, http: &reqwest::Client, token: &str, route: &str) -> Value {
        http.get(format!("http://{}/api/v1/{route}", self.api))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn connected(&self, http: &reqwest::Client, token: &str, peer: &Node) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let peers = self.get(http, token, "peers").await;
            if peers
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["node_id"] == peer.identity.node_id().to_hex() && p["connected"] == true)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no reconnect: {peers}; {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn stop(&self, mut process: Process) {
        // Graceful stop preserves the runtime/store fence for the next start.
        // SAFETY: the pid belongs to this test's still-owned child process.
        assert_eq!(
            unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                assert!(status.success(), "{}", self.logs());
                return;
            }
            assert!(Instant::now() < deadline, "stop timeout: {}", self.logs());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[tokio::test]
async fn owner_added_peer_survives_restart_and_config_still_wins() {
    let a = Node::new();
    let b = Node::new();
    // B accepts A in advance; A starts with no configured contacts.
    let mut cfg: toml::Value = std::fs::read_to_string(&b.config).unwrap().parse().unwrap();
    cfg["peers"] = toml::Value::try_from(vec![json!({"node_id": a.identity.node_id().to_hex(), "addr": a.peer.to_string(), "auto_connect": false})]).unwrap();
    std::fs::write(&b.config, toml::to_string(&cfg).unwrap()).unwrap();
    let unchanged = std::fs::read(&a.config).unwrap();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut pa = a.start(true);
    let mut pb = b.start(false);
    a.ready(&mut pa, &http, true).await;
    b.ready(&mut pb, &http, false).await;
    let token_a = a.token(&http).await;
    let token_b = b.token(&http).await;
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args([
            "peer",
            "add",
            "--node-id",
            &b.identity.node_id().to_hex(),
            "--addr",
            &b.peer.to_string(),
            "--label",
            "Dad",
            "--yes",
            "--config",
        ])
        .arg(&a.config)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("— connected"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    a.connected(&http, &token_a, &b).await;
    b.connected(&http, &token_b, &a).await;
    assert_eq!(
        a.get(&http, &token_a, "peers/connected").await,
        json!([b.identity.node_id().to_hex()])
    );
    assert_eq!(std::fs::read(&a.config).unwrap(), unchanged);
    a.stop(pa).await;
    let mut pa = a.start(true);
    a.ready(&mut pa, &http, true).await;
    let token_a = a.token(&http).await;
    a.connected(&http, &token_a, &b).await;
    b.connected(&http, &token_b, &a).await;
    let peers = a.get(&http, &token_a, "peers").await;
    assert_eq!(peers[0]["addr"], b.peer.to_string());
    assert_eq!(peers[0]["label"], "Dad");
    assert_eq!(std::fs::read(&a.config).unwrap(), unchanged);
    a.stop(pa).await;
    // Stop B too: an inbound reconnect cannot rewrite A's configured address.
    b.stop(pb).await;
    let wrong_addr = address();
    let mut cfg: toml::Value = std::fs::read_to_string(&a.config).unwrap().parse().unwrap();
    cfg["peers"] = toml::Value::try_from(vec![json!({"node_id": b.identity.node_id().to_hex(), "addr": wrong_addr.to_string(), "label": "Config contact"})]).unwrap();
    std::fs::write(&a.config, toml::to_string(&cfg).unwrap()).unwrap();
    let mut pa = a.start(true);
    a.ready(&mut pa, &http, true).await;
    let token_a = a.token(&http).await;
    let peers = a.get(&http, &token_a, "peers").await;
    assert_eq!(peers[0]["addr"], wrong_addr.to_string());
    assert_eq!(peers[0]["label"], "Config contact");
    a.stop(pa).await;
}

#[tokio::test]
async fn owner_console_lock_status_prints_unlocked_json() {
    let node = Node::new();
    let mut process = node.start(true);
    let http = reqwest::Client::new();
    node.ready(&mut process, &http, true).await;
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["lock-status", "--config"])
        .arg(&node.config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        status,
        json!({
            "state":"unlocked", "node_id":node.identity.node_id().to_hex(),
            "fingerprint":konsensus_api::pairing::identity_fingerprint(&node.identity.node_id().to_hex()),
            "locked_since":null, "attempts_left":null, "hosted_by":null
        })
    );
    assert_eq!(
        http.get(format!("http://{}/api/v1/node/lock", node.api))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // The additive operation must leave existing console requests available.
    assert!(matches!(
        konsensus_api::control::send(
            &node.dir.path().join("control.sock"),
            &konsensus_api::control::ControlRequest::Status
        )
        .await
        .unwrap(),
        konsensus_api::control::ControlResponse::Status { .. }
    ));
}
