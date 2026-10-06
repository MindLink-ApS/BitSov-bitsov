//! Real process: encrypted seed -> box-static tunnel -> normal live start.
#![cfg(unix)]
#[path = "../src/mnemonic_crypto.rs"]
mod mnemonic_crypto;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    locked::unlock_message,
    pairing::{
        self,
        device::{self, DeviceKey},
        PairingService,
    },
    remote_access as wire,
};
use konsensus_core::{NodeIdentity, OwnerApprovalKey};
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::{
    io::Write,
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const PASSWORD: &str = "remote-unlock-secret-never-log";
struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn logs(file: &std::fs::File) -> String {
    use std::os::unix::fs::FileExt;
    let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
    file.read_exact_at(&mut bytes, 0).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}
struct Fixture {
    dir: tempfile::TempDir,
    config: std::path::PathBuf,
    api: SocketAddr,
    remote: SocketAddr,
    peer: SocketAddr,
    identity: NodeIdentity,
    device: EcdsaKeyPair,
    record: DeviceKey,
    client: SigningKey,
    box_pin: [u8; 32],
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut init = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args([
                "init",
                "--non-interactive",
                "--tier",
                "light",
                "--password-fd",
                "0",
                "--dir",
            ])
            .arg(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        init.stdin
            .take()
            .unwrap()
            .write_all(PASSWORD.as_bytes())
            .unwrap();
        let out = init.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let config = dir.path().join("konsensus.toml");
        let mut cfg: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        cfg["node"] = toml::Value::try_from(std::collections::BTreeMap::from([(
            "hosted_by",
            "Rasmus's Pi",
        )]))
        .unwrap();
        let api = address();
        let remote = address();
        let peer = address();
        cfg["api"]["listen_addr"] = api.to_string().into();
        cfg["network"]["listen_addr"] = peer.to_string().into();
        cfg["lightning"]["backend"] = "mock".into();
        cfg["chain"]["backend"] = "mock".into();
        cfg["remote_access"] = toml::Value::try_from(std::collections::BTreeMap::from([
            ("listen_addr", remote.to_string()),
            ("advertised_endpoint", remote.to_string()),
        ]))
        .unwrap();
        std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
        let phrase = mnemonic_crypto::read_mnemonic(
            Path::new(cfg["identity"]["mnemonic_file"].as_str().unwrap()),
            Some(PASSWORD),
        )
        .unwrap();
        let identity = NodeIdentity::from_mnemonic(&phrase, "").unwrap();
        let node_id = identity.node_id().to_hex();
        let fingerprint = pairing::identity_fingerprint(&node_id);
        let pairing = PairingService::open(dir.path(), fingerprint.clone(), false).unwrap();
        let client = SigningKey::from_bytes(&[17; 32]);
        let transport =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([18; 32])).to_bytes();
        let paired = pairing
            .create_verified_remote_pairing(
                "phone",
                &hex::encode(client.verifying_key().to_bytes()),
                &transport,
            )
            .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let device =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public = hex::encode(device.public_key().as_ref());
        let secret = mnemonic_crypto::owner_secret(PASSWORD, &node_id).unwrap();
        let owner = OwnerApprovalKey::from_mnemonic(&phrase, "", &secret).unwrap();
        let record = DeviceKey {
            key_id: hex::encode(&blake3::hash(device.public_key().as_ref()).as_bytes()[..16]),
            client_id: paired.client_id,
            public_key: public.clone(),
            name: "phone".into(),
            registered_at: 1,
            epoch: paired.epoch,
            client_pubkey: paired.client_pubkey.clone(),
            owner_approval: hex::encode(
                owner
                    .sign(
                        device::owner_approval_message(
                            &fingerprint,
                            &paired.client_pubkey,
                            paired.epoch,
                            &public,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
            ),
            enrolled_by: "console".into(),
        };
        let box_pin = pairing.box_transport_pubkey();
        let metadata = json!({"node_id": node_id, "identity_fingerprint": fingerprint,"box_transport_pubkey":hex::encode(box_pin),"box_transport_signature":URL_SAFE_NO_PAD.encode(identity.sign(wire::box_transport_proof_message(&node_id,&hex::encode(box_pin)).as_bytes()).to_bytes())});
        std::fs::create_dir_all(dir.path().join("identity")).unwrap();
        std::fs::write(
            dir.path().join("identity/identity.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        drop(pairing);
        let path = dir.path().join("pairing/clients.json");
        let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["device_keys"] = json!([record]);
        std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
        Self {
            dir,
            config,
            api,
            remote,
            peer,
            identity,
            device,
            record,
            client,
            box_pin,
        }
    }
    fn start(&self, log: &std::fs::File, local: bool) -> Node {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.env("RUST_LOG", "info,konsensus_api::locked=debug");
        cmd.args(["start", "--config"])
            .arg(&self.config)
            .arg("--remote-unlock")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log.try_clone().unwrap());
        if local {
            cmd.arg("--local-owner-device");
        }
        Node(cmd.spawn().unwrap())
    }
    async fn ready(&self, node: &mut Node, path: &str, log: &std::fs::File) -> Value {
        let http = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Ok(r) = http.get(format!("http://{}{path}", self.api)).send().await {
                if r.status().is_success() {
                    return r.json().await.unwrap();
                }
            }
            assert!(node.0.try_wait().unwrap().is_none(), "{}", logs(log));
            assert!(Instant::now() < deadline, "{}", logs(log));
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    fn unlock_body(&self, challenge: &str, password: &str) -> Value {
        let r = &self.record;
        let msg = unlock_message(
            &pairing::identity_fingerprint(&self.identity.node_id().to_hex()),
            &r.client_id,
            r.epoch,
            &r.key_id,
            challenge,
            &hex::encode(self.box_pin),
        );
        let signature = self
            .device
            .sign(&ring::rand::SystemRandom::new(), msg.as_bytes())
            .unwrap();
        json!({"challenge":challenge,"key_id":r.key_id,"signature":hex::encode(signature.as_ref()),"password":password})
    }
}
struct Tunnel {
    stream: TcpStream,
    noise: NoiseSession,
}
impl Tunnel {
    async fn connect(f: &Fixture, auth: Value) -> (Self, Value) {
        let mut stream = TcpStream::connect(f.remote).await.unwrap();
        let mut noise = NoiseSession::initiator(&[18; 32]).unwrap();
        wire::write_frame(&mut stream, &noise.write_handshake(&[]).unwrap())
            .await
            .unwrap();
        noise
            .read_handshake(
                &wire::read_frame(&mut stream, MAX_NOISE_MSG_LEN)
                    .await
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(noise.remote_static_key().unwrap(), &f.box_pin);
        wire::write_frame(&mut stream, &noise.write_handshake(&[]).unwrap())
            .await
            .unwrap();
        noise.try_finish_handshake().unwrap();
        wire::write_frame(
            &mut stream,
            &wire::encode_transport(&mut noise, &serde_json::to_vec(&auth).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let frame = wire::read_frame(&mut stream, wire::MAX_TRANSPORT_FRAME)
            .await
            .unwrap();
        let response = serde_json::from_slice(
            &wire::decode_transport(&mut noise, &frame, wire::MAX_AUTH_PLAINTEXT).unwrap(),
        )
        .unwrap();
        (Self { stream, noise }, response)
    }
    async fn post(&mut self, path: &str, body: Value) -> (u16, Value) {
        let body = Zeroizing::new(body.to_string());
        let request = Zeroizing::new(format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",body.len(),body.as_str()));
        wire::write_frame(
            &mut self.stream,
            &wire::encode_transport(&mut self.noise, request.as_bytes()).unwrap(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        loop {
            let frame = tokio::time::timeout(
                Duration::from_secs(30),
                wire::read_frame(&mut self.stream, wire::MAX_TRANSPORT_FRAME),
            )
            .await
            .unwrap()
            .unwrap();
            response.push_str(
                std::str::from_utf8(
                    &wire::decode_transport(&mut self.noise, &frame, wire::MAX_TUNNEL_PLAINTEXT)
                        .unwrap(),
                )
                .unwrap(),
            );
            if let Some((header, body)) = response.split_once("\r\n\r\n") {
                let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
                let length = header
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|v| v.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    assert!(!response.contains(PASSWORD));
                    return (
                        status,
                        if body.is_empty() {
                            Value::Null
                        } else {
                            serde_json::from_str(body).unwrap()
                        },
                    );
                }
            }
        }
    }
    async fn challenge(&mut self) -> String {
        let (status, body) = self.post("/api/v1/node/unlock/challenge", json!({})).await;
        assert_eq!(status, 200);
        body["challenge"].as_str().unwrap().into()
    }
}

#[tokio::test]
async fn locked_mode_tunnel_unlock_starts_normal_node_and_preserves_authority_flags() {
    let f = Fixture::new();
    let log = tempfile::tempfile().unwrap();
    let http = reqwest::Client::new();
    for local in [true, false] {
        let mut node = f.start(&log, local);
        let lock = f.ready(&mut node, "/api/v1/node/lock", &log).await;
        assert_eq!(lock["node_id"], f.identity.node_id().to_hex());
        assert_eq!(lock["hosted_by"], "Rasmus's Pi");
        let refused = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(["pair-ticket", "--config"])
            .arg(&f.config)
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("while locked"));
        assert!(!lock.to_string().contains(PASSWORD));
        assert!(
            TcpStream::connect(f.peer).await.is_err(),
            "peer port must remain unbound"
        );
        assert!(!f.dir.path().join("control.sock").exists());
        for field in ["code", "client_name", "client_pubkey", "signature"] {
            let (_, response) = Tunnel::connect(&f, json!({"v":1,field:""})).await;
            assert_eq!(response["code"], "authentication_failed");
        }
        for path in [
            "/api/v1/health",
            "/api/v1/auth/local",
            "/api/v1/pair/request",
        ] {
            assert_eq!(
                http.post(format!("http://{}{path}", f.api))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                404
            );
        }
        let (mut tunnel, auth) = Tunnel::connect(&f, json!({"v":1})).await;
        assert_eq!(auth["status"], "ok");
        let c = tunnel.challenge().await;
        assert_eq!(
            tunnel
                .post("/api/v1/node/unlock", f.unlock_body(&c, "wrong"))
                .await
                .0,
            401
        );
        let c = tunnel.challenge().await;
        assert_eq!(
            tunnel
                .post("/api/v1/node/unlock", f.unlock_body(&c, PASSWORD))
                .await,
            (204, Value::Null)
        );
        let closed = tokio::time::timeout(
            Duration::from_millis(250),
            wire::read_frame(&mut tunnel.stream, wire::MAX_TRANSPORT_FRAME),
        )
        .await;
        assert!(
            closed.is_ok_and(|r| r.is_err()),
            "locked tunnel must close within 250ms"
        );
        let health = f.ready(&mut node, "/api/v1/health", &log).await;
        assert_eq!(health["hosted_by"], "Rasmus's Pi");
        let issued = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(["pair-ticket", "--config"])
            .arg(&f.config)
            .output()
            .unwrap();
        assert!(
            issued.status.success(),
            "{}",
            String::from_utf8_lossy(&issued.stderr)
        );
        let uri = String::from_utf8(issued.stdout).unwrap();
        let ticket = wire::PairLink::from_uri(uri.trim()).unwrap();
        assert_eq!(ticket.node_id, f.identity.node_id().to_hex());
        assert_eq!(ticket.hosted_by.as_deref(), Some("Rasmus's Pi"));
        assert_eq!(ticket.box_transport_pubkey, hex::encode(f.box_pin));
        assert!(ticket.box_transport_signature.is_some());
        assert!(!logs(&log).contains("bitsov://pair/"));
        assert!(!logs(&log).contains(&ticket.code));
        assert!(
            TcpStream::connect(f.peer).await.is_ok(),
            "normal startup binds peers"
        );
        let challenge: Value = http
            .get(format!("http://{}/api/v1/pair/challenge", f.api))
            .query(&[("client_id", &f.record.client_id)])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token:Value=http.post(format!("http://{}/api/v1/pair/token",f.api)).json(&json!({"client_id":f.record.client_id,"challenge":challenge["challenge"],"signature":hex::encode(f.client.sign(challenge["challenge"].as_str().unwrap().as_bytes()).to_bytes())})).send().await.unwrap().json().await.unwrap();
        let token = token["token"].as_str().unwrap();
        let keys: Value = http
            .get(format!("http://{}/api/v1/pair/device-keys", f.api))
            .bearer_auth(token)
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
        let intent = pairing::RelationIntent {
            device_key_id: f.record.key_id.clone(),
            peer: "aa".repeat(32),
            level: 1,
            budget_msat: 100_000,
            per_act_max_msat: 10_000,
            window_secs: 60,
            issued_at: chrono::Utc::now().timestamp(),
            nonce: hex::encode(rand::random::<[u8; 16]>()),
        };
        let message = device::intent_message(
            &pairing::identity_fingerprint(&f.identity.node_id().to_hex()),
            &f.record.client_id,
            &intent,
        );
        let sig = hex::encode(
            f.device
                .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
                .unwrap()
                .as_ref(),
        );
        let response = http
            .post(format!("http://{}/api/v1/pair/relation-intent", f.api))
            .bearer_auth(token)
            .json(&json!({"intent":intent,"signature":sig}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().is_success(), local);
        drop(node);
        let file_log = std::fs::read_to_string(f.dir.path().join("node.log")).unwrap();
        for captured in [logs(&log), file_log] {
            assert!(!captured.contains("bitsov://pair/"));
            assert!(!captured.contains(&ticket.code));
        }
    }
    assert!(!logs(&log).contains(PASSWORD));
    assert!(!std::fs::read_to_string(f.dir.path().join("node.log"))
        .unwrap()
        .contains(PASSWORD));
    fn scan(path: &Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                scan(&p)
            } else if p.is_file() {
                assert!(!std::fs::read(p)
                    .unwrap()
                    .windows(PASSWORD.len())
                    .any(|w| w == PASSWORD.as_bytes()));
            }
        }
    }
    scan(f.dir.path());
}

#[tokio::test]
async fn locked_mode_forged_record_and_identity_mismatch_stay_locked() {
    for mismatched_identity in [false, true] {
        let f = Fixture::new();
        let log = tempfile::tempfile().unwrap();
        if mismatched_identity {
            let other=NodeIdentity::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","").unwrap();
            let node_id = other.node_id().to_hex();
            let fp = pairing::identity_fingerprint(&node_id);
            let path = f.dir.path().join("identity/identity.json");
            let mut meta: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            meta["node_id"] = node_id.clone().into();
            meta["identity_fingerprint"] = fp.clone().into();
            meta["box_transport_signature"] = URL_SAFE_NO_PAD
                .encode(
                    other
                        .sign(
                            wire::box_transport_proof_message(&node_id, &hex::encode(f.box_pin))
                                .as_bytes(),
                        )
                        .to_bytes(),
                )
                .into();
            std::fs::write(path, serde_json::to_vec(&meta).unwrap()).unwrap();
            // A forged identity pairing can authenticate transport, but must
            // still fail owner approval or the decrypted node-id comparison.
            let path = f.dir.path().join("pairing/clients.json");
            let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            file["clients"][0]["identity_fingerprint"] = fp.clone().into();
            let cfg: toml::Value = std::fs::read_to_string(&f.config).unwrap().parse().unwrap();
            let phrase = mnemonic_crypto::read_mnemonic(
                Path::new(cfg["identity"]["mnemonic_file"].as_str().unwrap()),
                Some(PASSWORD),
            )
            .unwrap();
            let secret =
                mnemonic_crypto::owner_secret(PASSWORD, &f.identity.node_id().to_hex()).unwrap();
            let owner = OwnerApprovalKey::from_mnemonic(&phrase, "", &secret).unwrap();
            file["device_keys"][0]["owner_approval"] = hex::encode(
                owner
                    .sign(
                        device::owner_approval_message(
                            &fp,
                            &f.record.client_pubkey,
                            f.record.epoch,
                            &f.record.public_key,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
            )
            .into();
            std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
        } else {
            let path = f.dir.path().join("pairing/clients.json");
            let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            file["device_keys"][0]["owner_approval"] = "00".repeat(64).into();
            std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
        }
        let mut node = f.start(&log, true);
        let lock = f.ready(&mut node, "/api/v1/node/lock", &log).await;
        let (mut tunnel, auth) = Tunnel::connect(&f, json!({"v":1})).await;
        assert_eq!(auth["status"], "ok");
        let c = tunnel.challenge().await;
        let mut body = f.unlock_body(&c, PASSWORD);
        if mismatched_identity {
            let msg = unlock_message(
                lock["fingerprint"].as_str().unwrap(),
                &f.record.client_id,
                f.record.epoch,
                &f.record.key_id,
                &c,
                &hex::encode(f.box_pin),
            );
            body["signature"] = hex::encode(
                f.device
                    .sign(&ring::rand::SystemRandom::new(), msg.as_bytes())
                    .unwrap()
                    .as_ref(),
            )
            .into();
        }
        assert_eq!(
            tunnel.post("/api/v1/node/unlock", body).await.0,
            if mismatched_identity { 401 } else { 403 }
        );
        assert!(TcpStream::connect(f.peer).await.is_err());
        assert!(node.0.try_wait().unwrap().is_none());
        if !mismatched_identity {
            assert!(logs(&log).contains("UNLOCK_DEVICE_RECORD_INVALID"));
        }
        assert!(!logs(&log).contains(PASSWORD));
    }
}

#[test]
fn locked_mode_plaintext_seed_refuses_before_serving() {
    let f = Fixture::new();
    let mut cfg: toml::Value = std::fs::read_to_string(&f.config).unwrap().parse().unwrap();
    let path = std::path::PathBuf::from(cfg["identity"]["mnemonic_file"].as_str().unwrap());
    let phrase = mnemonic_crypto::read_mnemonic(&path, Some(PASSWORD)).unwrap();
    let plain = path.with_extension("txt");
    std::fs::write(&plain, phrase.as_bytes()).unwrap();
    cfg["identity"]["mnemonic_file"] = plain.to_str().unwrap().into();
    std::fs::write(&f.config, toml::to_string(&cfg).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["start", "--config"])
        .arg(&f.config)
        .arg("--remote-unlock")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("seed_not_encrypted"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(PASSWORD));
}

#[tokio::test]
async fn locked_mode_shutdown_mid_unlock_closes_listeners_without_starting_node() {
    let f = Fixture::new();
    let log = tempfile::tempfile().unwrap();
    let mut node = f.start(&log, true);
    f.ready(&mut node, "/api/v1/node/lock", &log).await;
    let (mut tunnel, auth) = Tunnel::connect(&f, json!({"v":1})).await;
    assert_eq!(auth["status"], "ok");
    let c = tunnel.challenge().await;
    let body = Zeroizing::new(f.unlock_body(&c, PASSWORD).to_string());
    let request = Zeroizing::new(format!("POST /api/v1/node/unlock HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body.as_str()));
    wire::write_frame(
        &mut tunnel.stream,
        &wire::encode_transport(&mut tunnel.noise, request.as_bytes()).unwrap(),
    )
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !logs(&log).contains("UNLOCK_VERIFYING") {
        assert!(
            Instant::now() < deadline,
            "verification never began: {}",
            logs(&log)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(Command::new("/bin/kill")
        .args(["-TERM", &node.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "shutdown timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(status.success(), "{}", logs(&log));
    for address in [f.api, f.remote, f.peer] {
        assert!(TcpStream::connect(address).await.is_err());
    }
    assert!(!logs(&log).contains("node built"));
    assert!(!logs(&log).contains(PASSWORD));
    assert!(!f.dir.path().join("node.log").exists());
}
