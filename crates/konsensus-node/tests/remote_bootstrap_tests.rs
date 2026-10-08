//! Real process: pre-bootstrap ticket -> remote first run over the box-static
//! tunnel -> supervised restart into locked mode -> first remote unlock.
#![cfg(unix)]
#[path = "../src/mnemonic_crypto.rs"]
mod mnemonic_crypto;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    locked::unlock_message,
    pairing::{self, device},
    remote_access as wire,
};
use konsensus_core::{NodeIdentity, OwnerApprovalKey};
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const PASSWORD: &str = "remote-bootstrap-secret-never-log";
const CLIENT_STATIC: [u8; 32] = [18; 32];

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
    config: PathBuf,
    api: SocketAddr,
    remote: SocketAddr,
    peer: SocketAddr,
    page_port: u16,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (api, remote, peer) = (address(), address(), address());
        let page_port = address().port();
        let d = dir.path().display();
        let config = dir.path().join("konsensus.toml");
        std::fs::write(
            &config,
            format!(
                r#"
tier = "light"
[setup_page]
port = {page_port}
[node]
hosted_by = "Rasmus's Pi"
[identity]
mnemonic_file = "{d}/mnemonic.enc"
[network]
listen_addr = "{peer}"
[lightning]
backend = "mock"
[chain]
backend = "mock"
[storage]
backend = "sqlite"
path = "{d}/node.db"
[backup]
scb_dir = "{d}/backups"
[api]
listen_addr = "{api}"
[remote_access]
listen_addr = "{remote}"
advertised_endpoint = "{remote}"
"#
            ),
        )
        .unwrap();
        Self {
            dir,
            config,
            api,
            remote,
            peer,
            page_port,
        }
    }

    fn start(&self, log: &std::fs::File, flags: &[&str]) -> Node {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.args(["start", "--config"])
            .arg(&self.config)
            .args(flags)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log.try_clone().unwrap());
        Node(cmd.spawn().unwrap())
    }

    async fn ready(&self, node: &mut Node, path: &str, log: &std::fs::File) -> Value {
        let http = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Ok(r) = http.get(format!("http://{}{path}", self.api)).send().await {
                if r.status().is_success() {
                    return r.json().await.unwrap_or(Value::Null);
                }
            }
            assert!(node.0.try_wait().unwrap().is_none(), "{}", logs(log));
            assert!(Instant::now() < deadline, "{}", logs(log));
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

async fn exited(node: &mut Node, log: &std::fs::File) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "node did not exit: {}",
            logs(log)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct Tunnel {
    stream: TcpStream,
    noise: NoiseSession,
}

impl Tunnel {
    /// Pin the box static from the ticket; never learn it from the node.
    async fn connect(remote: SocketAddr, box_pin: &str, auth: Value) -> (Self, Value) {
        let mut stream = TcpStream::connect(remote).await.unwrap();
        let mut noise = NoiseSession::initiator(&CLIENT_STATIC).unwrap();
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
        assert_eq!(hex::encode(noise.remote_static_key().unwrap()), box_pin);
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

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let body = Zeroizing::new(body.map(Value::to_string).unwrap_or_default());
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body.as_str()
        ));
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
                    let value = if body.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.into()))
                    };
                    return (status, value);
                }
            }
        }
    }
}

fn verify_box_proof(node_id: &str, box_pubkey: &str, signature: &str) {
    let key: [u8; 32] = hex::decode(node_id).unwrap().try_into().unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(
            wire::box_transport_proof_message(node_id, box_pubkey).as_bytes(),
            &signature,
        )
        .unwrap();
}

fn scan_for_password(path: &Path) {
    for entry in std::fs::read_dir(path).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan_for_password(&p)
        } else if p.is_file() {
            assert!(
                !std::fs::read(&p)
                    .unwrap()
                    .windows(PASSWORD.len())
                    .any(|w| w == PASSWORD.as_bytes()),
                "password found in {}",
                p.display()
            );
        }
    }
}

#[tokio::test]
async fn non_home_remote_bootstrap_requires_home_for_box_approval() {
    let f = Fixture::new();
    let log = tempfile::tempfile().unwrap();
    let mut node = f.start(&log, &["--remote-unlock", "--local-owner-device"]);
    assert!(!exited(&mut node, &log).await.success());
    assert!(logs(&log).contains("remote first run requires --home"));
    assert!(!f.dir.path().join("NODE_INITIALIZED").exists());
}

#[tokio::test]
async fn home_bootstrap_restarts_locked_and_unlocks_without_console_authority() {
    bootstrap_restarts_locked_and_first_unlock_succeeds(&["--home"]).await;
}

async fn bootstrap_restarts_locked_and_first_unlock_succeeds(flags: &[&str]) {
    let f = Fixture::new();
    let log = tempfile::tempfile().unwrap();
    let http = reqwest::Client::new();

    // 1. Operator issues a pre-bootstrap ticket; it carries only the box static.
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
    let mut ticket =
        wire::PairLink::from_uri(String::from_utf8(issued.stdout).unwrap().trim()).unwrap();
    assert!(ticket.node_id.is_empty());
    let box_pin = ticket.box_transport_pubkey.clone();

    // 2. Fresh box: bootstrap with the tunnel, no startup password.
    let mut node = f.start(&log, flags);
    f.ready(&mut node, "/livez", &log).await;
    let home = flags.contains(&"--home");
    let mut page_url = String::new();
    let mut cookie = String::new();
    let mut csrf = String::new();
    if home {
        let ip = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .map(|i| i.ip())
            .find(|ip| ip.is_ipv4() && konsensus_api::bootstrap::setup::lan_source(*ip))
            .expect("home process test requires a LAN interface");
        page_url = format!("http://{}", SocketAddr::new(ip, f.page_port));
        let response = http.get(&page_url).send().await.unwrap();
        assert_eq!(response.status(), 200);
        cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into();
        let html = response.text().await.unwrap();
        csrf = html
            .split("const csrf = '")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap()
            .into();
        let issued: Value = http
            .post(format!("{page_url}/setup/start"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        ticket = wire::PairLink::from_uri(issued["uri"].as_str().unwrap()).unwrap();
        assert!(!f.dir.path().join("pairing/remote-access-link").exists());
    }
    assert!(!f.dir.path().join("control.sock").exists());
    assert!(
        TcpStream::connect(f.peer).await.is_err(),
        "bootstrap binds no peer port"
    );
    let (_, refused) = Tunnel::connect(f.remote, &box_pin, json!({"v": 1})).await;
    assert_eq!(refused["code"], "authentication_failed");
    let client = SigningKey::from_bytes(&[17; 32]);
    let client_pubkey = hex::encode(client.verifying_key().to_bytes());
    let client_transport = hex::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CLIENT_STATIC)).as_bytes(),
    );
    let proof = wire::pairing_proof_message("", &client_transport, &ticket.code, &client_pubkey);
    let (mut tunnel, auth) = Tunnel::connect(
        f.remote,
        &box_pin,
        json!({"v": 1, "code": ticket.code, "client_name": "iPhone", "client_pubkey": client_pubkey,
               "signature": URL_SAFE_NO_PAD.encode(client.sign(proof.as_bytes()).to_bytes())}),
    )
    .await;
    assert_eq!(auth["status"], "ok", "{auth}");
    assert_eq!(auth["scopes"], json!(["read", "receive", "identity"]));
    assert_eq!(auth["box_transport_pubkey"], box_pin);
    assert!(!f.dir.path().join("pairing/remote-access-link").exists());
    let client_id = auth["client_id"].as_str().unwrap().to_string();

    // 3. Bootstrap token over the tunnel.
    let (_, challenge) = tunnel
        .send(
            "GET",
            &format!("/api/v1/pair/challenge?client_id={client_id}"),
            None,
            None,
        )
        .await;
    let challenge = challenge["challenge"].as_str().unwrap();
    let (status, token) = tunnel
        .send(
            "POST",
            "/api/v1/pair/token",
            None,
            Some(&json!({"client_id": client_id, "challenge": challenge,
                         "signature": hex::encode(client.sign(challenge.as_bytes()).to_bytes())})),
        )
        .await;
    assert_eq!(status, 200, "{token}");
    let bst = token["token"].as_str().unwrap().to_string();
    let (_, state) = tunnel
        .send("GET", "/api/v1/bootstrap/state", None, None)
        .await;
    assert_eq!(state["local_owner"]["tunnel_password"], true);
    assert_eq!(state["can_restore"], false);

    // 4. Commit to the password, then show the phrase.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let device_public = hex::encode(device_key.public_key().as_ref());
    let mut commitment =
        json!({"password_commitment":blake3::hash(PASSWORD.as_bytes()).to_hex().to_string()});
    if home {
        commitment["sas_version"] = json!(1);
        commitment["device"] = json!({"public_key":device_public,"name":"iPhone"});
    }
    let loopback = http
        .post(format!("http://{}/api/v1/identity/create-pending", f.api))
        .bearer_auth(&bst)
        .json(&commitment)
        .send()
        .await
        .unwrap();
    assert_eq!(loopback.status(), 400);
    let (status, p) = tunnel
        .send(
            "POST",
            "/api/v1/identity/create-pending",
            Some(&bst),
            Some(&commitment),
        )
        .await;
    if !home {
        assert_eq!((status, p), (403, json!("sas_required")));
        assert!(!f.dir.path().join("NODE_INITIALIZED").exists());
        return;
    }
    assert_eq!(status, 200, "{p}");
    let phrase = p["mnemonic"].as_str().unwrap().to_string();
    let node_id = p["node_id"].as_str().unwrap().to_string();
    let fingerprint = pairing::identity_fingerprint(&node_id);
    let words: Vec<_> = phrase.split_whitespace().collect();
    let backup: Vec<_> = p["backup_check"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| words[i.as_u64().unwrap() as usize])
        .collect();
    let claim = konsensus_api::sas::load(f.dir.path()).unwrap();
    let digest = konsensus_api::sas::digest(
        &konsensus_api::sas::NoiseBinding {
            handshake_hash: *tunnel.noise.handshake_hash().unwrap(),
            box_public_key: hex::decode(&box_pin).unwrap().try_into().unwrap(),
            client_static: hex::decode(&client_transport).unwrap().try_into().unwrap(),
        },
        &device_key.public_key().as_ref().try_into().unwrap(),
        &hex::decode(p["box_nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        &claim.commitment(),
    );
    let registration = hex::encode(
        device_key
            .sign(
                &rng,
                device::sas_registration_message(&fingerprint, &client_id, &device_public, &digest)
                    .as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let finalize = json!({"ceremony_id": p["ceremony_id"], "backup_words": backup,
        "device": {"public_key": device_public, "name": "iPhone", "proof": registration},
        "password": PASSWORD, "sas_version":1,"sas_digest":digest.to_hex().to_string()});

    // 5. The loopback listener refuses a finalize password.
    let loopback = http
        .post(format!("http://{}/api/v1/identity/finalize", f.api))
        .bearer_auth(&bst)
        .json(&finalize)
        .send()
        .await
        .unwrap();
    assert_eq!(loopback.status(), 400);
    assert_eq!(loopback.text().await.unwrap(), "tunnel_required");
    assert!(!f.dir.path().join("identity").exists());

    let (status, body) = tunnel
        .send(
            "POST",
            "/api/v1/identity/finalize",
            Some(&bst),
            Some(&finalize),
        )
        .await;
    assert_eq!((status, body), (409, json!("box_approval_pending")));
    let page_state: Value = http
        .get(format!("{page_url}/setup/state"))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        page_state["words"],
        json!(konsensus_api::sas::words(&digest))
    );
    let approved = http
        .post(format!("{page_url}/setup/approve"))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"ceremony_id":p["ceremony_id"],"sas_digest":digest.to_hex().to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), 204);
    assert!(!f.dir.path().join("NODE_INITIALIZED").exists());
    // 6. Finalize over the tunnel: encrypted seed, signed box pin, exit 75.
    let (status, result) = tunnel
        .send(
            "POST",
            "/api/v1/identity/finalize",
            Some(&bst),
            Some(&finalize),
        )
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["node_id"], node_id);
    assert!(result.get("mnemonic").is_none());
    assert_eq!(result["box_transport_pubkey"], box_pin);
    verify_box_proof(
        &node_id,
        &box_pin,
        result["box_transport_signature"].as_str().unwrap(),
    );
    let status = exited(&mut node, &log).await;
    assert_eq!(status.code(), Some(75), "{}", logs(&log));
    drop(node);

    let cfg: toml::Value = std::fs::read_to_string(&f.config).unwrap().parse().unwrap();
    let enc = f.dir.path().join("identity/mnemonic.enc");
    assert_eq!(
        cfg["identity"]["mnemonic_file"].as_str().unwrap(),
        enc.to_str().unwrap()
    );
    assert!(f.dir.path().join("NODE_INITIALIZED").exists());
    assert!(!f.dir.path().join("identity/mnemonic.txt").exists());
    assert_eq!(
        mnemonic_crypto::read_mnemonic(&enc, Some(PASSWORD))
            .unwrap()
            .as_str(),
        phrase
    );
    assert_eq!(
        NodeIdentity::from_mnemonic(&phrase, "")
            .unwrap()
            .node_id()
            .to_hex(),
        node_id
    );
    let clients: Value =
        serde_json::from_slice(&std::fs::read(f.dir.path().join("pairing/clients.json")).unwrap())
            .unwrap();
    let record: device::DeviceKey =
        serde_json::from_value(clients["device_keys"][0].clone()).unwrap();
    assert_eq!(record.enrolled_by, "remote_first_run");
    let owner = OwnerApprovalKey::from_mnemonic(
        &phrase,
        "",
        &mnemonic_crypto::owner_secret(PASSWORD, &node_id).unwrap(),
    )
    .unwrap();
    device::verify_owner_approval(
        &owner.verifying_key(),
        &device::owner_approval_message(
            &fingerprint,
            &record.client_pubkey,
            record.epoch,
            &record.public_key,
        ),
        &record.owner_approval,
    )
    .unwrap();

    // 7. Supervised restart: same command, now locked; first unlock works.
    let mut node = f.start(&log, flags);
    let lock = f.ready(&mut node, "/api/v1/node/lock", &log).await;
    let status_html = http
        .get(&page_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(status_html.contains("LOCKED"));
    assert!(status_html.contains("Use the BitSov app"));
    for secret in ["Approve", "bitsov://", phrase.as_str(), PASSWORD] {
        assert!(!status_html.contains(secret));
    }
    assert_eq!(lock["state"], "locked");
    assert!(!f.dir.path().join("control.sock").exists());
    let locked_pid = node.0.id();
    assert_eq!(lock["node_id"], node_id);
    assert_eq!(lock["fingerprint"], fingerprint);
    let (mut tunnel, auth) = Tunnel::connect(f.remote, &box_pin, json!({"v": 1})).await;
    assert_eq!(auth["status"], "ok", "{auth}");
    assert_eq!(auth["client_id"], client_id);
    verify_box_proof(
        &node_id,
        &box_pin,
        auth["box_transport_signature"].as_str().unwrap(),
    );
    let (status, challenge) = tunnel
        .send(
            "POST",
            "/api/v1/node/unlock/challenge",
            None,
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(challenge["key_ids"], json!([record.key_id]));
    let c = challenge["challenge"].as_str().unwrap();
    let message = unlock_message(
        &fingerprint,
        &client_id,
        record.epoch,
        &record.key_id,
        c,
        &box_pin,
    );
    let signature = device_key.sign(&rng, message.as_bytes()).unwrap();
    let (status, _) = tunnel
        .send(
            "POST",
            "/api/v1/node/unlock",
            None,
            Some(&json!({"challenge": c, "key_id": record.key_id,
                         "signature": hex::encode(signature.as_ref()), "password": PASSWORD})),
        )
        .await;
    assert_eq!(status, 204, "{}", logs(&log));

    // 8. Normal startup in the same process, with the device's authority.
    let health = f.ready(&mut node, "/api/v1/health", &log).await;
    assert_eq!(health["hosted_by"], "Rasmus's Pi");
    assert_eq!(node.0.id(), locked_pid);
    assert!(node.0.try_wait().unwrap().is_none());
    assert!(!f.dir.path().join("control.sock").exists());
    assert!(
        TcpStream::connect(f.peer).await.is_ok(),
        "live node binds peers"
    );
    let challenge: Value = http
        .get(format!("http://{}/api/v1/pair/challenge", f.api))
        .query(&[("client_id", &client_id)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = challenge["challenge"].as_str().unwrap();
    let token: Value = http
        .post(format!("http://{}/api/v1/pair/token", f.api))
        .json(&json!({"client_id": client_id, "challenge": challenge,
                      "signature": hex::encode(client.sign(challenge.as_bytes()).to_bytes())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap();
    let device_keys = || async {
        http.get(format!("http://{}/api/v1/pair/device-keys", f.api))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    };
    let keys = device_keys().await;
    assert_eq!(keys["local_owner_device"], true, "{keys}");
    assert_eq!(keys["owner_device_count"], 1, "{keys}");

    // 9. A claimed box refuses legacy enrollment, including the local API.
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let second =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let second_public = hex::encode(second.public_key().as_ref());
    let proof = second
        .sign(
            &rng,
            device::registration_message(&fingerprint, &client_id, &second_public).as_bytes(),
        )
        .unwrap();
    let reg = http
        .post(format!("http://{}/api/v1/pair/device-key", f.api))
        .bearer_auth(token)
        .json(&json!({"public_key": second_public, "name": "iPad",
                      "proof": hex::encode(proof.as_ref())}))
        .send()
        .await
        .unwrap();
    assert!(reg.status().is_client_error());
    assert_eq!(device_keys().await["owner_device_count"], 1);
    let html = http
        .get(&page_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("UNLOCKED"));
    assert!(!html.contains("Approve"));
    drop(node);

    let file_log = std::fs::read_to_string(f.dir.path().join("node.log")).unwrap_or_default();
    for captured in [logs(&log), file_log] {
        assert!(!captured.contains(PASSWORD));
        assert!(!captured.contains(&phrase));
        assert!(!captured.contains(&ticket.code));
    }
    scan_for_password(f.dir.path());
}
