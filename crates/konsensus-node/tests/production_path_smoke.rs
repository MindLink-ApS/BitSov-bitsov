//! Production-path smoke test (#393): real `konsensus` processes, regtest
//! invoices on the shared mock ledger, loopback only, no network.
//!
//! Every client step goes through the Noise tunnel into the remote router,
//! the path the app uses away from home:
//! 1. pair a client with a one-time pair-ticket code;
//! 2. enroll a device key (the owner approves over control.sock);
//! 3. submit a device-signed relation intent for contact B;
//! 4. send a paid message to B and see it arrive at B.
//!
//! A 404 or 405 on any of these routes fails the test with the route named,
//! so an unmounted remote route (the #388 regression) cannot pass silently.
#![cfg(unix)]
#[path = "../src/mnemonic_crypto.rs"]
mod mnemonic_crypto;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    control::ControlResponse,
    pairing::{self, device, RelationIntent},
    remote_access as wire,
};
use konsensus_core::{NodeIdentity, OwnerApprovalKey};
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const PASSWORD: &str = "production-path-smoke-never-log";
const CLIENT_STATIC: [u8; 32] = [23; 32];
const CHAT_MSAT: u64 = 2_000;
const INITIAL_MSAT: u64 = 10_000_000;
const MESSAGE: &str = "production path smoke over the remote router";

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

fn logs(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// One node's data directory, ports and identity.
struct Box_ {
    dir: PathBuf,
    config: PathBuf,
    api: SocketAddr,
    peer: SocketAddr,
    jwt_secret: String,
    identity: NodeIdentity,
    log: PathBuf,
}

impl Box_ {
    /// `konsensus init`; with `encrypted`, the seed is encrypted with PASSWORD.
    fn init(dir: PathBuf, encrypted: bool) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.args(["init", "--non-interactive", "--tier", "light", "--dir"])
            .arg(&dir);
        if encrypted {
            cmd.args(["--password-fd", "0"]);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if encrypted {
            stdin.write_all(PASSWORD.as_bytes()).unwrap();
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let config = dir.join("konsensus.toml");
        let cfg: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        let phrase = mnemonic_crypto::read_mnemonic(
            Path::new(cfg["identity"]["mnemonic_file"].as_str().unwrap()),
            encrypted.then_some(PASSWORD),
        )
        .unwrap();
        let identity = NodeIdentity::from_mnemonic(&phrase, "").unwrap();
        Self {
            log: dir.join("stdout.log"),
            dir,
            config,
            api: address(),
            peer: address(),
            jwt_secret: hex::encode(rand::random::<[u8; 32]>()),
            identity,
        }
    }

    fn node_id(&self) -> String {
        self.identity.node_id().to_hex()
    }

    /// Mock-only settings shared by both nodes: shared mock Lightning
    /// (regtest invoices), mock chain, loopback ports, mutual contacts.
    fn configure(&self, ledger: &Path, contact: &Box_, extra: impl FnOnce(&mut toml::Value)) {
        let mut cfg: toml::Value = std::fs::read_to_string(&self.config)
            .unwrap()
            .parse()
            .unwrap();
        let table = |pairs: Vec<(&str, toml::Value)>| {
            toml::Value::Table(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        };
        let mut set = |section: &str, key: &str, value: toml::Value| {
            cfg[section]
                .as_table_mut()
                .unwrap()
                .insert(key.into(), value);
        };
        set("api", "listen_addr", self.api.to_string().into());
        set("api", "jwt_secret", self.jwt_secret.clone().into());
        set("api", "rate_limit_rps", 100.into());
        set("network", "listen_addr", self.peer.to_string().into());
        set("setup_page", "port", i64::from(address().port()).into());
        set("pricing", "chat_msat", (CHAT_MSAT as i64).into());
        set("payment_gate", "verify_lightning_settlement", true.into());
        set("payment_gate", "min_admission_cost_msat", 0.into());
        cfg["lightning"] = table(vec![
            ("backend", "shared_mock".into()),
            ("ledger_path", ledger.display().to_string().into()),
            ("initial_balance_msat", (INITIAL_MSAT as i64).into()),
        ]);
        cfg["peers"] = toml::Value::Array(vec![table(vec![
            ("node_id", contact.node_id().into()),
            ("addr", contact.peer.to_string().into()),
            ("label", "contact".into()),
            ("auto_connect", true.into()),
        ])]);
        extra(&mut cfg);
        // Mock only: never a real wallet or chain.
        assert_eq!(cfg["lightning"]["backend"].as_str(), Some("shared_mock"));
        assert_eq!(cfg["chain"]["backend"].as_str(), Some("mock"));
        std::fs::write(&self.config, toml::to_string(&cfg).unwrap()).unwrap();
    }

    /// Start detached from any terminal, so owner codes go to the
    /// owner-only approval file as on a headless box.
    fn start(&self, args: &[&str], password: bool) -> Node {
        use std::os::unix::process::CommandExt;
        let out = std::fs::File::create(&self.log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.env("RUST_LOG", "info")
            .args(["start", "--config"])
            .arg(&self.config)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(out.try_clone().unwrap())
            .stderr(out);
        // SAFETY: setsid has no pointer arguments and touches no Rust state.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if password {
            stdin.write_all(PASSWORD.as_bytes()).unwrap();
        }
        drop(stdin);
        Node(child)
    }

    async fn ready(&self, node: &mut Node) {
        let http = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(r) = http
                .get(format!("http://{}/api/v1/health", self.api))
                .send()
                .await
            {
                if r.status().is_success() {
                    return;
                }
            }
            assert!(node.0.try_wait().unwrap().is_none(), "{}", logs(&self.log));
            assert!(Instant::now() < deadline, "{}", logs(&self.log));
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The owner's own local API (not part of the client path).
    async fn local_get(&self, path: &str) -> (u16, Value) {
        let token = konsensus_api::auth::create_token(
            &self.node_id(),
            &self.jwt_secret,
            vec![konsensus_api::auth::Scope::Read],
        )
        .unwrap();
        let r = reqwest::Client::new()
            .get(format!("http://{}{path}", self.api))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// One JSON line on the owner control socket, as the owner CLI sends it.
    async fn control(&self, request: Value) -> ControlResponse {
        let stream = tokio::net::UnixStream::connect(self.dir.join("control.sock"))
            .await
            .unwrap();
        let (read, mut write) = stream.into_split();
        let mut line = serde_json::to_vec(&request).unwrap();
        line.push(b'\n');
        write.write_all(&line).await.unwrap();
        let reply = BufReader::new(read)
            .lines()
            .next_line()
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&reply).unwrap()
    }
}

/// The app's side of the remote-access tunnel.
struct Tunnel {
    stream: TcpStream,
    noise: NoiseSession,
    handshake_hash: [u8; 32],
}

impl Tunnel {
    async fn connect(remote: SocketAddr, pin: &str, auth: Value) -> (Self, Value) {
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
        assert_eq!(hex::encode(noise.remote_static_key().unwrap()), pin);
        wire::write_frame(&mut stream, &noise.write_handshake(&[]).unwrap())
            .await
            .unwrap();
        noise.try_finish_handshake().unwrap();
        let handshake_hash = *noise.handshake_hash().unwrap();
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
        (
            Self {
                stream,
                noise,
                handshake_hash,
            },
            response,
        )
    }

    /// One HTTP request through the tunnel. A 404 or 405 means the remote
    /// router does not mount a route the app uses: fail loudly, naming it.
    async fn call(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let (status, value) = self.raw(method, path, token, body).await;
        assert!(
            status != 404 && status != 405,
            "remote router answered {status} for {method} {path}: a route the app uses \
             remotely is not mounted ({value})"
        );
        (status, value)
    }

    async fn raw(
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
                Duration::from_secs(60),
                wire::read_frame(&mut self.stream, wire::MAX_TRANSPORT_FRAME),
            )
            .await
            .unwrap_or_else(|_| panic!("no tunnel response for {method} {path}"))
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

    /// Challenge-response for a fresh paired token.
    async fn token(&mut self, client_id: &str, client: &SigningKey) -> String {
        let (status, challenge) = self
            .call(
                "GET",
                &format!("/api/v1/pair/challenge?client_id={client_id}"),
                None,
                None,
            )
            .await;
        assert_eq!(status, 200, "{challenge}");
        let challenge = challenge["challenge"].as_str().unwrap();
        let (status, token) = self
            .call(
                "POST",
                "/api/v1/pair/token",
                None,
                Some(&json!({"client_id": client_id, "challenge": challenge,
                             "signature": hex::encode(client.sign(challenge.as_bytes()).to_bytes())})),
            )
            .await;
        assert_eq!(status, 200, "{token}");
        token["token"].as_str().unwrap().to_string()
    }
}

async fn eventually<F, Fut>(what: &str, secs: u64, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !check().await {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_enroll_relation_intent_then_paid_message_over_the_remote_router() {
    let root = tempfile::tempdir().unwrap();
    let ledger = root.path().join("ledger.sqlite");
    let a = Box_::init(root.path().join("a"), true);
    let b = Box_::init(root.path().join("b"), false);
    let remote = address();
    a.configure(&ledger, &b, |cfg| {
        let remote_access = cfg["remote_access"].as_table_mut().unwrap();
        remote_access.insert("listen_addr".into(), remote.to_string().into());
        remote_access.insert("advertised_endpoint".into(), remote.to_string().into());
        cfg["pairing"]["second_device_enrollment"] = true.into();
    });
    b.configure(&ledger, &a, |_| {});

    let mut node_b = b.start(&[], false);
    b.ready(&mut node_b).await;
    // The owner of A starts it with its password and owner authority.
    let mut node_a = a.start(
        &[
            "--password-fd",
            "0",
            "--local-owner-device",
            "--owner-control",
        ],
        true,
    );
    a.ready(&mut node_a).await;

    // ── 1. Pair over the Noise tunnel with a one-time ticket code. ──
    let issued = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["pair-ticket", "--config"])
        .arg(&a.config)
        .output()
        .unwrap();
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let link = wire::PairLink::from_uri(String::from_utf8(issued.stdout).unwrap().trim()).unwrap();
    link.verify_endpoints(&a.node_id()).unwrap();
    // An unlocked node answers with its seed-derived static.
    let pin = hex::encode(a.identity.x25519_public().as_bytes());
    assert_eq!(link.transport_pubkey, pin);
    let client = SigningKey::from_bytes(&[29; 32]);
    let client_pubkey = hex::encode(client.verifying_key().to_bytes());
    let client_transport = hex::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CLIENT_STATIC)).as_bytes(),
    );
    let proof =
        wire::pairing_proof_message(&a.node_id(), &client_transport, &link.code, &client_pubkey);
    let (mut tunnel, auth) = Tunnel::connect(
        remote,
        &pin,
        json!({"v": 1, "code": link.code, "client_name": "smoke phone",
               "client_pubkey": client_pubkey,
               "signature": URL_SAFE_NO_PAD.encode(client.sign(proof.as_bytes()).to_bytes())}),
    )
    .await;
    assert_eq!(auth["status"], "ok", "{auth}");
    let client_id = auth["client_id"].as_str().unwrap().to_string();
    let read = tunnel.token(&client_id, &client).await;

    // ── 2. Enroll a device key; the owner approves at control.sock. ──
    let fingerprint = pairing::identity_fingerprint(&a.node_id());
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let sign = |message: &str| hex::encode(device.sign(&rng, message.as_bytes()).unwrap().as_ref());
    let public = hex::encode(device.public_key().as_ref());
    let (status, reg) = tunnel
        .call(
            "POST",
            "/api/v1/pair/device-key",
            Some(&read),
            Some(&json!({"sas_version": 1, "public_key": public, "name": "smoke phone",
                         "proof": sign(&device::registration_message(&fingerprint, &client_id, &public))})),
        )
        .await;
    assert_eq!(status, 200, "{reg}");
    let op_id = reg["op_id"].as_str().unwrap().to_string();
    let key_id = reg["key_id"].as_str().unwrap().to_string();
    // The owner reads the box's claim code; the app binds it to this tunnel.
    let claim = konsensus_api::sas::load(&a.dir).unwrap();
    let binding = konsensus_api::sas::NoiseBinding {
        handshake_hash: tunnel.handshake_hash,
        box_public_key: hex::decode(&link.box_transport_pubkey)
            .unwrap()
            .try_into()
            .unwrap(),
        client_static: hex::decode(&client_transport).unwrap().try_into().unwrap(),
    };
    let nonce: [u8; 16] = hex::decode(reg["box_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let digest = konsensus_api::sas::digest(
        &binding,
        &device.public_key().as_ref().try_into().unwrap(),
        &nonce,
        &claim.commitment(),
    );
    let (status, body) = tunnel
        .call(
            "POST",
            &format!("/api/v1/pair/device-key/{op_id}/finalize"),
            Some(&read),
            Some(
                &json!({"sas_version": 1, "sas_digest": digest.to_hex().to_string(),
                         "proof": sign(&device::sas_registration_message(
                             &fingerprint, &client_id, &public, &digest))}),
            ),
        )
        .await;
    assert_eq!(status, 204, "{body}");
    let approval = std::fs::read_to_string(a.dir.join(format!("pairing/owner-approval-{op_id}")))
        .unwrap_or_else(|e| panic!("owner approval file: {e}\n{}", logs(&a.log)));
    let code = approval
        .lines()
        .find_map(|l| {
            l.split_once("type this code when it asks: ")
                .map(|(_, c)| c.to_string())
        })
        .unwrap();
    let tuple = match a.control(json!({"op": "describe", "op_id": op_id})).await {
        ControlResponse::Describe {
            device: Some(tuple),
            ..
        } => tuple,
        other => panic!("{other:?}"),
    };
    assert_eq!(tuple.device_public_key, public);
    let phrase =
        mnemonic_crypto::read_mnemonic(&a.dir.join("mnemonic.enc"), Some(PASSWORD)).unwrap();
    let secret = mnemonic_crypto::owner_secret(PASSWORD, &a.node_id()).unwrap();
    let owner = OwnerApprovalKey::from_mnemonic(&phrase, "", &secret).unwrap();
    let owner_signature = hex::encode(
        owner
            .sign(
                device::owner_approval_message(
                    &tuple.node,
                    &tuple.client_pubkey,
                    tuple.epoch,
                    &tuple.device_public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let approved = a
        .control(json!({"op": "approve-device-key", "op_id": op_id,
                        "confirmation": code, "owner_signature": owner_signature}))
        .await;
    assert!(
        matches!(approved, ControlResponse::Ok { .. }),
        "{approved:?}"
    );
    let (status, done) = tunnel
        .call(
            "GET",
            &format!("/api/v1/pair/device-key/{op_id}"),
            Some(&read),
            None,
        )
        .await;
    assert_eq!(
        (status, done["status"].as_str()),
        (200, Some("registered")),
        "{done}"
    );

    // ── 3. Device-signed relation intent for contact B, over the tunnel. ──
    let intent = RelationIntent {
        device_key_id: key_id,
        peer: b.node_id(),
        level: 1,
        budget_msat: 100_000,
        per_act_max_msat: 20_000,
        window_secs: 3_600,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: hex::encode(rand::random::<[u8; 16]>()),
    };
    let signature = sign(&device::intent_message(&fingerprint, &client_id, &intent));
    let (status, body) = tunnel
        .call(
            "POST",
            "/api/v1/pair/relation-intent",
            Some(&read),
            Some(&json!({"intent": intent, "signature": signature})),
        )
        .await;
    assert_eq!(status, 200, "{body}\n{}", logs(&a.log));
    assert_eq!(body["grant"]["recipients_only"], true, "{body}");
    assert_eq!(
        body["grant"]["per_recipient_msat"][b.node_id()],
        100_000,
        "{body}"
    );

    // ── 4. A paid message to B; B must receive it. ──
    let spend = tunnel.token(&client_id, &client).await;
    eventually("A connects to B", 60, || async {
        let (_, peers) = a.local_get("/api/v1/peers/connected").await;
        peers.to_string().contains(&b.node_id())
    })
    .await;
    let (status, sent) = tunnel
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(&spend),
            Some(
                &json!({"recipient": b.node_id(), "is_room": false, "kind": 0,
                         "plaintext": MESSAGE, "max_total_msat": 20_000}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{sent}\n{}", logs(&a.log));
    assert_eq!(sent["delivered"], true, "{sent}");
    eventually("B stores A's paid message", 30, || async {
        let (status, inbox) = b
            .local_get(&format!("/api/v1/messages?peer={}", a.node_id()))
            .await;
        status == 200 && inbox.as_array().is_some_and(|m| !m.is_empty())
    })
    .await;
    let (_, inbox) = b
        .local_get(&format!("/api/v1/messages?peer={}", a.node_id()))
        .await;
    assert!(
        inbox.to_string().contains(&a.node_id()),
        "B's message is from A: {inbox}"
    );
    // Payment is the connection: B was paid on the shared ledger.
    let (_, balance) = b.local_get("/api/v1/payments/balance").await;
    assert!(
        balance["balance_msat"].as_u64().unwrap() >= INITIAL_MSAT + CHAT_MSAT,
        "B was not paid: {balance}"
    );

    drop(tunnel);
    drop(node_a);
    drop(node_b);
    for path in [
        &a.log,
        &a.dir.join("node.log"),
        &b.log,
        &b.dir.join("node.log"),
    ] {
        let text = logs(path);
        assert!(
            !text.contains(PASSWORD),
            "{} leaks the password",
            path.display()
        );
        assert!(
            !text.contains(&link.code),
            "{} leaks the pair code",
            path.display()
        );
        assert!(
            !text.contains(&signature),
            "{} leaks the intent signature",
            path.display()
        );
    }
}
