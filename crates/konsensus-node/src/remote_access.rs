//! Noise_XX remote-access listener.
//!
//! The public socket never speaks HTTP. After authenticating the client's
//! Noise static against a durable pairing, it bridges bounded encrypted
//! records to a second Axum listener bound to `127.0.0.1:0`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Verifier;
use konsensus_api::pairing::{PairedClient, PairingService};
use konsensus_api::remote_access::{self as wire, AuthRequest, AuthResponse, PairLink, VERSION};
use konsensus_core::NodeIdentity;
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::RemoteAccessConfig;

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKES_PER_IP_PER_MINUTE: u32 = 20;
const MAX_RATE_LIMIT_IPS: usize = 2048;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct HandshakeLimiter {
    entries: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl HandshakeLimiter {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        if entries.len() >= MAX_RATE_LIMIT_IPS && !entries.contains_key(&ip) {
            return false;
        }
        let (start, count) = entries.entry(ip).or_insert((now, 0));
        if now.duration_since(*start) >= Duration::from_secs(60) {
            *start = now;
            *count = 0;
        }
        if *count >= HANDSHAKES_PER_IP_PER_MINUTE {
            return false;
        }
        *count += 1;
        true
    }
}

pub struct RemoteAccessServer {
    listener: TcpListener,
    identity: Arc<NodeIdentity>,
    pairing: Arc<PairingService>,
    internal_api: SocketAddr,
    pairing_code: Arc<Mutex<Option<String>>>,
    pair_link: Option<String>,
}

impl RemoteAccessServer {
    pub async fn bind(
        config: &RemoteAccessConfig,
        identity: Arc<NodeIdentity>,
        pairing: Arc<PairingService>,
        internal_api: SocketAddr,
    ) -> Result<Self> {
        let listen_addr = config
            .listen_addr
            .context("remote access is disabled (no listen_addr)")?;
        let endpoint = config
            .advertised_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("remote access advertised_endpoint is missing")?;
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("could not bind remote access listener at {listen_addr}"))?;

        let (pairing_code, pair_link) = if pairing.pairing_open() {
            let mut code_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut code_bytes);
            let code = URL_SAFE_NO_PAD.encode(code_bytes);
            let node_id = identity.node_id().to_hex();
            let transport_pubkey = hex::encode(identity.x25519_public().as_bytes());
            let proof = wire::transport_proof_message(&node_id, &transport_pubkey);
            let signature = URL_SAFE_NO_PAD.encode(identity.sign(proof.as_bytes()).to_bytes());
            let link = PairLink {
                v: VERSION,
                endpoint: endpoint.to_owned(),
                node_id,
                transport_pubkey,
                transport_signature: signature,
                code: code.clone(),
            }
            .to_uri()
            .context("could not encode remote pairing link")?;
            (Some(code), Some(link))
        } else {
            (None, None)
        };

        Ok(Self {
            listener,
            identity,
            pairing,
            internal_api,
            pairing_code: Arc::new(Mutex::new(pairing_code)),
            pair_link,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn pair_link(&self) -> Option<&str> {
        self.pair_link.as_deref()
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        let limits = Arc::new(HandshakeLimiter::new());
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = self.listener.accept() => {
                    let (stream, peer_addr) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            warn!(%error, "remote access accept failed");
                            continue;
                        }
                    };
                    if !limits.allow(peer_addr.ip(), Instant::now()) {
                        debug!(%peer_addr, "remote access pre-handshake rate limit");
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                        debug!(%peer_addr, "remote access connection limit");
                        continue;
                    };
                    let identity = Arc::clone(&self.identity);
                    let pairing = Arc::clone(&self.pairing);
                    let pairing_code = Arc::clone(&self.pairing_code);
                    let internal_api = self.internal_api;
                    let connection_shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(
                            stream,
                            identity,
                            pairing,
                            pairing_code,
                            internal_api,
                            connection_shutdown,
                        ).await {
                            debug!(%peer_addr, %error, "remote access connection closed");
                        }
                    });
                }
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = joined {
                        warn!(%error, "remote access connection task panicked");
                    }
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        info!("remote access listener stopped");
    }
}

async fn handle_connection(
    stream: TcpStream,
    identity: Arc<NodeIdentity>,
    pairing: Arc<PairingService>,
    pairing_code: Arc<Mutex<Option<String>>>,
    internal_api: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (mut remote_reader, mut remote_writer) = stream.into_split();
    let handshake = async {
        let mut noise = NoiseSession::responder(identity.x25519_secret_bytes())?;
        let msg1 = wire::read_frame(&mut remote_reader, MAX_NOISE_MSG_LEN).await?;
        noise.read_handshake(&msg1)?;
        let msg2 = noise.write_handshake(&[])?;
        wire::write_frame(&mut remote_writer, &msg2).await?;
        let msg3 = wire::read_frame(&mut remote_reader, MAX_NOISE_MSG_LEN).await?;
        noise.read_handshake(&msg3)?;
        noise.try_finish_handshake()?;
        anyhow::Ok(noise)
    };
    let mut noise = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake) => {
            result.context("remote Noise handshake timed out")??
        }
    };
    let remote_static = *noise
        .remote_static_key()
        .context("Noise handshake did not authenticate a remote static key")?;

    let auth = async {
        let ciphertext = wire::read_frame(&mut remote_reader, wire::MAX_TRANSPORT_FRAME).await?;
        let plaintext = wire::decode_transport(&mut noise, &ciphertext, wire::MAX_AUTH_PLAINTEXT)
            .map_err(anyhow::Error::msg)?;
        serde_json::from_slice::<AuthRequest>(&plaintext).context("invalid remote auth request")
    };
    let request = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        result = tokio::time::timeout(AUTH_TIMEOUT, auth) => {
            result.context("remote authentication timed out")??
        }
    };

    let authenticated = authenticate(
        &request,
        &remote_static,
        identity.node_id().to_hex().as_str(),
        &pairing,
        &pairing_code,
    );
    let response = match &authenticated {
        Ok(client) => AuthResponse::Ok {
            v: VERSION,
            client_id: client.client_id.clone(),
            scopes: client.scopes.clone(),
        },
        Err(error) => AuthResponse::Error {
            v: VERSION,
            code: "authentication_failed".into(),
            message: error.to_string(),
        },
    };
    let response_json = serde_json::to_vec(&response)?;
    let response_ciphertext =
        wire::encode_transport(&mut noise, &response_json).map_err(anyhow::Error::msg)?;
    wire::write_frame(&mut remote_writer, &response_ciphertext).await?;
    let client = authenticated?;

    let internal = TcpStream::connect(internal_api)
        .await
        .context("could not connect to internal remote API")?;
    let (mut internal_reader, mut internal_writer) = internal.into_split();
    let mut internal_buf = vec![0u8; wire::MAX_TUNNEL_PLAINTEXT];
    info!(client_id = %client.client_id, "remote access tunnel authenticated");

    // Keep framed reads in their own task. `read_exact` is not cancellation
    // safe; placing it directly in the bridge's select could consume a partial
    // length/body whenever the internal HTTP side became readable.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(4);
    let _remote_read_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            let frame = wire::read_frame(&mut remote_reader, wire::MAX_TRANSPORT_FRAME).await;
            let stop = frame.is_err();
            if frame_tx.send(frame).await.is_err() || stop {
                break;
            }
        }
    }));

    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            incoming = frame_rx.recv() => {
                let ciphertext = match incoming {
                    Some(Ok(frame)) => frame,
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(()),
                };
                let plaintext = wire::decode_transport(
                    &mut noise,
                    &ciphertext,
                    wire::MAX_TUNNEL_PLAINTEXT,
                ).map_err(anyhow::Error::msg)?;
                internal_writer.write_all(&plaintext).await?;
                internal_writer.flush().await?;
            }
            read = internal_reader.read(&mut internal_buf) => {
                let read = read?;
                if read == 0 {
                    return Ok(());
                }
                let ciphertext = wire::encode_transport(&mut noise, &internal_buf[..read])
                    .map_err(anyhow::Error::msg)?;
                wire::write_frame(&mut remote_writer, &ciphertext).await?;
            }
        }
    }
}

fn authenticate(
    request: &AuthRequest,
    remote_static: &[u8; 32],
    node_id: &str,
    pairing: &PairingService,
    pairing_code: &Mutex<Option<String>>,
) -> Result<PairedClient> {
    if request.v != VERSION {
        anyhow::bail!("unsupported remote auth version {}", request.v);
    }

    let Some(code) = request.code.as_deref() else {
        if request.client_name.is_some()
            || request.client_pubkey.is_some()
            || request.signature.is_some()
        {
            anyhow::bail!("existing-pairing auth must omit pairing fields");
        }
        return pairing
            .validate_remote_transport(remote_static)
            .map_err(anyhow::Error::from);
    };

    let name = request
        .client_name
        .as_deref()
        .context("client_name is required for first pairing")?;
    let pubkey_hex = request
        .client_pubkey
        .as_deref()
        .context("client_pubkey is required for first pairing")?;
    if pubkey_hex != pubkey_hex.to_ascii_lowercase() {
        anyhow::bail!("client_pubkey must be lowercase hex");
    }
    let signature = request
        .signature
        .as_deref()
        .context("signature is required for first pairing")?;

    let pubkey_bytes = hex::decode(pubkey_hex).context("invalid client_pubkey hex")?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("client_pubkey must be 32 bytes"))?;
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes).context("invalid client_pubkey")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .context("invalid auth signature base64url")?;
    let signature =
        ed25519_dalek::Signature::from_slice(&signature_bytes).context("invalid auth signature")?;
    let transport_hex = hex::encode(remote_static);
    let proof = wire::pairing_proof_message(node_id, &transport_hex, code, pubkey_hex);
    verifying
        .verify(proof.as_bytes(), &signature)
        .context("remote pairing proof did not verify")?;

    // A response can be lost after the durable pairing is written and the
    // one-time code is consumed. Let that exact Ed25519 + Noise identity retry
    // idempotently; the request cannot create or take over another mapping.
    if let Ok(existing) = pairing.validate_remote_transport(remote_static) {
        if existing.client_pubkey != pubkey_hex {
            anyhow::bail!("remote pairing key does not match the existing transport binding");
        }
        return Ok(existing);
    }

    let mut code_guard = pairing_code.lock().unwrap_or_else(|e| e.into_inner());
    let expected = code_guard
        .as_deref()
        .context("first-pairing code is unavailable or already used")?;
    if blake3::hash(code.as_bytes()) != blake3::hash(expected.as_bytes()) {
        anyhow::bail!("pairing code did not match");
    }

    let client = pairing
        .create_verified_remote_pairing(name, pubkey_hex, remote_static)
        .map_err(anyhow::Error::from)?;
    *code_guard = None;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    fn identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate().unwrap().1)
    }

    fn request(
        node: &NodeIdentity,
        transport: &[u8; 32],
        code: &str,
        key: &SigningKey,
    ) -> AuthRequest {
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let proof = wire::pairing_proof_message(
            &node.node_id().to_hex(),
            &hex::encode(transport),
            code,
            &pubkey,
        );
        AuthRequest {
            v: VERSION,
            code: Some(code.into()),
            client_name: Some("remote test".into()),
            client_pubkey: Some(pubkey),
            signature: Some(URL_SAFE_NO_PAD.encode(key.sign(proof.as_bytes()).to_bytes())),
        }
    }

    #[test]
    fn wrong_code_and_proof_fail_then_pairing_is_single_use_and_revocable() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = PairingService::open(dir.path(), fingerprint, false).unwrap();
        let code = Mutex::new(Some("correct-code".to_string()));
        let transport = [9u8; 32];
        let key = SigningKey::from_bytes(&[7u8; 32]);

        let wrong_code = request(&node, &transport, "wrong-code", &key);
        assert!(authenticate(
            &wrong_code,
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code
        )
        .is_err());
        assert!(code.lock().unwrap().is_some());

        let mut wrong_proof = request(&node, &transport, "correct-code", &key);
        wrong_proof.signature = Some(URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert!(authenticate(
            &wrong_proof,
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code
        )
        .is_err());
        assert!(code.lock().unwrap().is_some());

        let paired = authenticate(
            &request(&node, &transport, "correct-code", &key),
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code,
        )
        .unwrap();
        assert_eq!(
            paired.scopes,
            vec![
                konsensus_api::auth::Scope::Read,
                konsensus_api::auth::Scope::Receive
            ]
        );
        assert!(code.lock().unwrap().is_none());

        let retried_after_lost_response = authenticate(
            &request(&node, &transport, "correct-code", &key),
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code,
        )
        .unwrap();
        assert_eq!(
            retried_after_lost_response.client_id, paired.client_id,
            "the exact paired identities must recover from a lost auth response"
        );

        let reopened = PairingService::open(
            dir.path(),
            konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex()),
            false,
        )
        .unwrap();
        assert_eq!(
            reopened
                .validate_remote_transport(&transport)
                .unwrap()
                .client_id,
            paired.client_id,
            "the remote transport mapping must survive restart"
        );

        let returning = AuthRequest {
            v: VERSION,
            code: None,
            client_name: None,
            client_pubkey: None,
            signature: None,
        };
        assert_eq!(
            authenticate(
                &returning,
                &transport,
                &node.node_id().to_hex(),
                &reopened,
                &code
            )
            .unwrap()
            .client_id,
            paired.client_id
        );
        reopened.revoke(&paired.client_id).unwrap();
        assert!(authenticate(
            &returning,
            &transport,
            &node.node_id().to_hex(),
            &reopened,
            &code
        )
        .is_err());
        assert!(
            reopened.validate_remote_transport(&[8u8; 32]).is_err(),
            "an unknown remote key must never authenticate"
        );
    }

    #[tokio::test]
    async fn pairing_link_signature_and_noise_tunnel_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = Arc::new(PairingService::open(dir.path(), fingerprint, false).unwrap());

        // A deliberately harmless loopback endpoint standing in for Axum.
        let internal = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let internal_addr = internal.local_addr().unwrap();
        let internal_task = tokio::spawn(async move {
            let (mut stream, _) = internal.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /safe HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\nsafe")
                .await
                .unwrap();
        });

        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:18443".into()),
        };
        let server = RemoteAccessServer::bind(&config, Arc::clone(&node), pairing, internal_addr)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let link = PairLink::from_uri(server.pair_link().unwrap()).unwrap();
        let proof = wire::transport_proof_message(&link.node_id, &link.transport_pubkey);
        let signature = ed25519_dalek::Signature::from_slice(
            &URL_SAFE_NO_PAD.decode(&link.transport_signature).unwrap(),
        )
        .unwrap();
        node.ed25519_verifying_key()
            .verify(proof.as_bytes(), &signature)
            .unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.serve(shutdown_rx));
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        let client_secret = [0x42u8; 32];
        let client_static = *X25519PublicKey::from(&StaticSecret::from(client_secret)).as_bytes();
        let mut noise = NoiseSession::initiator(&client_secret).unwrap();
        let msg1 = noise.write_handshake(&[]).unwrap();
        wire::write_frame(&mut writer, &msg1).await.unwrap();
        let msg2 = wire::read_frame(&mut reader, MAX_NOISE_MSG_LEN)
            .await
            .unwrap();
        noise.read_handshake(&msg2).unwrap();
        assert_eq!(
            hex::encode(noise.remote_static_key().unwrap()),
            link.transport_pubkey,
            "the app must pin the responder static from the link"
        );
        let msg3 = noise.write_handshake(&[]).unwrap();
        wire::write_frame(&mut writer, &msg3).await.unwrap();
        noise.try_finish_handshake().unwrap();

        let key = SigningKey::from_bytes(&[0x24u8; 32]);
        let auth = request(&node, &client_static, &link.code, &key);
        let ciphertext =
            wire::encode_transport(&mut noise, &serde_json::to_vec(&auth).unwrap()).unwrap();
        wire::write_frame(&mut writer, &ciphertext).await.unwrap();
        let ciphertext = wire::read_frame(&mut reader, wire::MAX_TRANSPORT_FRAME)
            .await
            .unwrap();
        let plaintext =
            wire::decode_transport(&mut noise, &ciphertext, wire::MAX_AUTH_PLAINTEXT).unwrap();
        assert!(matches!(
            serde_json::from_slice::<AuthResponse>(&plaintext).unwrap(),
            AuthResponse::Ok { .. }
        ));

        let ciphertext =
            wire::encode_transport(&mut noise, b"GET /safe HTTP/1.1\r\nhost: node\r\n\r\n")
                .unwrap();
        wire::write_frame(&mut writer, &ciphertext).await.unwrap();
        let ciphertext = wire::read_frame(&mut reader, wire::MAX_TRANSPORT_FRAME)
            .await
            .unwrap();
        let response =
            wire::decode_transport(&mut noise, &ciphertext, wire::MAX_TUNNEL_PLAINTEXT).unwrap();
        assert!(response.ends_with(b"\r\n\r\nsafe"));

        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap();
        internal_task.await.unwrap();
    }
}
