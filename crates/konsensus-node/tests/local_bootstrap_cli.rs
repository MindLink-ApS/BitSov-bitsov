//! Real descriptor handoff, encrypted bootstrap, terminal exit and local restart.
#![cfg(unix)]
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::pairing::{self, device};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "local-bootstrap-process-test-secret";
struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(config: &Path, log: &std::fs::File, local: bool, password: bool) -> Node {
    start_source(
        config,
        log,
        local,
        if password { "descriptor" } else { "none" },
    )
}
fn start_source(config: &Path, log: &std::fs::File, local: bool, source: &str) -> Node {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    cmd.args(["start", "--config"]).arg(config);
    if local {
        cmd.arg("--local-owner-device");
    }
    match source {
        "descriptor" => {
            cmd.args(["--password-fd", "0"]);
        }
        "flag" => {
            cmd.args(["--password", PASSWORD]);
        }
        "file" => {
            use std::os::unix::fs::PermissionsExt;
            let path = config.with_file_name("password-input");
            std::fs::write(&path, PASSWORD).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            cmd.arg("--password-file").arg(path);
        }
        "none" => {}
        _ => panic!("unknown password source"),
    }
    cmd.stdin(Stdio::piped())
        .stdout(log.try_clone().unwrap())
        .stderr(log.try_clone().unwrap());
    // SAFETY: setsid is async-signal-safe; prohibit accidental terminal prompts.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut node = Node(cmd.spawn().unwrap());
    if source == "descriptor" {
        node.0
            .stdin
            .take()
            .unwrap()
            .write_all(PASSWORD.as_bytes())
            .unwrap();
    } else {
        drop(node.0.stdin.take());
    }
    node
}
fn configure(dir: &Path) -> (std::path::PathBuf, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = dir.join("custom.toml");
    let text = format!(
        r#"
tier = "light"
[identity]
mnemonic_file = "{}/custom-mnemonic.txt"
[network]
listen_addr = "127.0.0.1:0"
[lightning]
backend = "mock"
[chain]
backend = "mock"
[storage]
backend = "sqlite"
path = "{}/node.db"
[backup]
scb_dir = "{}/backups"
[api]
listen_addr = "{addr}"
"#,
        dir.display(),
        dir.display(),
        dir.display()
    );
    std::fs::write(&config, text).unwrap();
    (config, format!("http://{addr}"))
}
fn logs(file: &std::fs::File) -> String {
    use std::os::unix::fs::FileExt;
    let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
    file.read_exact_at(&mut bytes, 0).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}
async fn ready(node: &mut Node, http: &reqwest::Client, base: &str, log: &std::fs::File) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut listening = false;
        for route in ["/livez", "/api/v1/health"] {
            if let Ok(r) = http.get(format!("{base}{route}")).send().await {
                if r.status().is_success() {
                    listening = true;
                    break;
                }
            }
        }
        if listening {
            break;
        }
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "node exited: {}",
            logs(log)
        );
        assert!(Instant::now() < deadline, "timeout: {}", logs(log));
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
async fn post(http: &reqwest::Client, base: &str, route: &str, token: &str, body: Value) -> Value {
    let response = http
        .post(format!("{base}/api/v1/{route}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{route}: {status} {text}");
    serde_json::from_str(&text).unwrap()
}
async fn token(http: &reqwest::Client, base: &str, client: &str, key: &SigningKey) -> String {
    let challenge: Value = http
        .get(format!("{base}/api/v1/pair/challenge"))
        .query(&[("client_id", client)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let signature = hex::encode(
        key.sign(challenge["challenge"].as_str().unwrap().as_bytes())
            .to_bytes(),
    );
    post(
        http,
        base,
        "pair/token",
        "",
        json!({"client_id": client, "challenge": challenge["challenge"], "signature": signature}),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_string()
}
async fn pair(http: &reqwest::Client, base: &str) -> (String, SigningKey, String) {
    let key = SigningKey::from_bytes(&[43; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let request = post(
        http,
        base,
        "pair/request",
        "",
        json!({"client_name": "This Mac", "client_pubkey": public}),
    )
    .await;
    let challenge = std::fs::read(request["challenge_path"].as_str().unwrap()).unwrap();
    let message = pairing::PairingService::proof_message(
        request["pair_id"].as_str().unwrap(),
        &public,
        &challenge,
    );
    let signature = hex::encode(key.sign(&message).to_bytes());
    let paired = post(
        http,
        base,
        "pair/confirm",
        "",
        json!({"pair_id": request["pair_id"], "signature": signature}),
    )
    .await;
    let client = paired["client_id"].as_str().unwrap().to_string();
    let token = token(http, base, &client, &key).await;
    (client, key, token)
}
async fn terminal(node: &mut Node, log: &std::fs::File) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            assert!(status.success(), "{}", logs(log));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bootstrap must exit, never auto-start"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

#[tokio::test]
async fn descriptor_bootstrap_restart_intent_and_no_secret_logs() {
    let dir = tempfile::tempdir().unwrap();
    let (config, base) = configure(dir.path());
    let log = tempfile::tempfile().unwrap();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let mut node = start(&config, &log, true, true);
    ready(&mut node, &http, &base, &log).await;
    let (client, client_key, bst) = pair(&http, &base).await;
    let p = post(&http, &base, "identity/create-pending", &bst, json!({})).await;
    assert!(!dir.path().join("identity").exists());
    let phrase = p["mnemonic"].as_str().unwrap();
    let words: Vec<_> = phrase.split_whitespace().collect();
    let backup: Vec<_> = p["backup_check"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| words[i.as_u64().unwrap() as usize])
        .collect();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device_key.public_key().as_ref());
    let fp = pairing::identity_fingerprint(p["node_id"].as_str().unwrap());
    let proof = hex::encode(
        device_key
            .sign(
                &rng,
                device::registration_message(&fp, &client, &public).as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let result = post(&http, &base, "identity/finalize", &bst, json!({"ceremony_id": p["ceremony_id"], "backup_words": backup, "device": {"public_key": public, "name": "This Mac", "proof": proof}})).await;
    assert!(result.get("mnemonic").is_none());
    terminal(&mut node, &log).await;
    drop(node);
    let cfg: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
    assert_eq!(
        cfg["identity"]["mnemonic_file"].as_str().unwrap(),
        dir.path().join("identity/mnemonic.enc").to_str().unwrap()
    );
    assert!(dir.path().join("NODE_INITIALIZED").exists());
    assert!(!dir.path().join("identity/mnemonic.txt").exists());
    let mut intent = pairing::RelationIntent {
        device_key_id: result["device_key_id"].as_str().unwrap().into(),
        peer: "aa".repeat(32),
        level: 1,
        budget_msat: 100_000,
        per_act_max_msat: 10_000,
        window_secs: 3600,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: "a1".repeat(16),
    };
    for local in [true, false] {
        let mut node = start(&config, &log, local, true);
        ready(&mut node, &http, &base, &log).await;
        let live_token = token(&http, &base, &client, &client_key).await;
        let dead = http
            .get(format!("{base}/api/v1/pair/device-keys"))
            .bearer_auth(&bst)
            .send()
            .await
            .unwrap();
        assert_eq!(dead.status(), reqwest::StatusCode::UNAUTHORIZED);
        let keys: Value = http
            .get(format!("{base}/api/v1/pair/device-keys"))
            .bearer_auth(&live_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(keys["local_owner_device"], local);
        if !local {
            assert!(keys.to_string().contains("seed_password_not_typed"));
        }
        intent.nonce = if local { "a2" } else { "a3" }.repeat(16);
        intent.issued_at = chrono::Utc::now().timestamp();
        let signature = hex::encode(
            device_key
                .sign(
                    &rng,
                    device::intent_message(&fp, &client, &intent).as_bytes(),
                )
                .unwrap()
                .as_ref(),
        );
        let response = http
            .post(format!("{base}/api/v1/pair/relation-intent"))
            .bearer_auth(&live_token)
            .json(&json!({"intent": intent, "signature": signature}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().is_success(), local);
        assert!(!dir.path().join("control.sock").exists());
        drop(node);
    }
    let output = logs(&log) + &std::fs::read_to_string(dir.path().join("node.log")).unwrap();
    assert!(!output.contains(PASSWORD));
    assert!(!output.contains(phrase));
    // Every individual word is checked in the API tracing capture test. Startup
    // logs use ordinary BIP-39 vocabulary (e.g. "network"), so a random overlap
    // there would be a false positive, not a secret disclosure.
}

#[tokio::test]
async fn legacy_create_restore_encrypt_with_password_and_keep_plaintext_without() {
    for source in ["descriptor", "none", "flag", "file"] {
        let password = source != "none";
        for restore in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (config, base) = configure(dir.path());
            let log = tempfile::tempfile().unwrap();
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap();
            let mut node = start_source(&config, &log, false, source);
            ready(&mut node, &http, &base, &log).await;
            let (_, _, token) = pair(&http, &base).await;
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let body = if restore {
                json!({"mnemonic": phrase})
            } else {
                json!({})
            };
            let result = post(
                &http,
                &base,
                if restore {
                    "identity/restore"
                } else {
                    "identity/create"
                },
                &token,
                body,
            )
            .await;
            assert_eq!(result.get("mnemonic").is_none(), restore);
            terminal(&mut node, &log).await;
            assert!(dir
                .path()
                .join(if password {
                    "identity/mnemonic.enc"
                } else {
                    "identity/mnemonic.txt"
                })
                .exists());
            assert!(!dir
                .path()
                .join(if password {
                    "identity/mnemonic.txt"
                } else {
                    "identity/mnemonic.enc"
                })
                .exists());
            assert!(dir.path().join("NODE_INITIALIZED").exists());
            assert!(!logs(&log).contains(PASSWORD));
        }
    }
}
