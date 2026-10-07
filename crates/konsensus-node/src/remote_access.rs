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
use konsensus_api::rate_limit::RemoteTunnelClients;
use konsensus_api::remote_access::{self as wire, AuthRequest, AuthResponse, PairLink, VERSION};
use konsensus_core::NodeIdentity;
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::RemoteAccessConfig;

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKES_PER_IP_PER_MINUTE: u32 = 20;
const HANDSHAKE_WINDOW: Duration = Duration::from_secs(60);
const HANDSHAKE_COST: Duration = Duration::from_secs(60 / HANDSHAKES_PER_IP_PER_MINUTE as u64);
const MAX_RATE_LIMIT_IPS: usize = 2048;
const MAX_PENDING_REFUSALS: usize = 64;
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const PAIRING_CODE_TTL: Duration = Duration::from_secs(5 * 60);

struct ActivePairingCode {
    value: String,
    expires_at: tokio::time::Instant,
    content_digest: blake3::Hash,
    content_len: usize,
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct HandshakeLimiter {
    // Time at which each IP's handshake debt has fully drained. Debt is at
    // most one minute and only admitted attempts add to it.
    entries: Mutex<HashMap<IpAddr, Instant>>,
}

impl HandshakeLimiter {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, drained_at| *drained_at > now);
        if entries.len() >= MAX_RATE_LIMIT_IPS && !entries.contains_key(&ip) {
            // Do not evict an active budget for an attacker rotating IPs.
            // A new IP can retry when the first tracked entry drains.
            return Err(*entries.values().min().unwrap() - now);
        }
        let drained_at = entries.entry(ip).or_insert(now);
        let next = *drained_at + HANDSHAKE_COST;
        let ceiling = now + HANDSHAKE_WINDOW;
        if next > ceiling {
            return Err(next - ceiling);
        }
        *drained_at = next;
        Ok(())
    }
}

async fn write_handshake_refusal<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    retry_after: Duration,
) -> Result<()> {
    // Round up so a client honoring whole seconds does not retry too early.
    let retry_after_secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() != 0);
    let refusal = wire::HandshakeRefusal::RateLimited {
        v: VERSION,
        retry_after_secs: retry_after_secs.clamp(1, HANDSHAKE_WINDOW.as_secs()),
    };
    let bytes = serde_json::to_vec(&refusal)?;
    tokio::time::timeout(REFUSAL_TIMEOUT, async {
        wire::write_frame(stream, &bytes).await?;
        // Let the initiator finish sending message 1 before closing. Dropping
        // TCP with that frame unread can reset its write before it reads the
        // hint. Drain one bounded frame without parsing or doing any Noise work.
        wire::read_frame(stream, MAX_NOISE_MSG_LEN).await?;
        stream.shutdown().await
    })
    .await
    .context("remote handshake refusal timed out")??;
    Ok(())
}

fn box_transport_proof(identity: &NodeIdentity, pairing: &PairingService) -> (String, String) {
    let public_key = hex::encode(pairing.box_transport_pubkey());
    let message = wire::box_transport_proof_message(&identity.node_id().to_hex(), &public_key);
    let signature = URL_SAFE_NO_PAD.encode(identity.sign(message.as_bytes()).to_bytes());
    (public_key, signature)
}

/// Publish only public identity data on every unlocked start, even when remote
/// access is disabled. Preserve bootstrap's committed_at and future metadata.
pub fn write_identity_metadata(
    data_dir: &std::path::Path,
    identity: &NodeIdentity,
    pairing: &PairingService,
) -> Result<()> {
    write_identity_metadata_with_sync(
        data_dir,
        identity,
        pairing,
        None,
        konsensus_api::pairing::fsync_dir_strict,
    )
}

fn write_identity_metadata_with_sync(
    data_dir: &std::path::Path,
    identity: &NodeIdentity,
    pairing: &PairingService,
    endpoints: Option<&[String]>,
    sync_dir: impl Fn(&std::path::Path) -> std::io::Result<()>,
) -> Result<()> {
    use konsensus_api::pairing::{restrict_dir, write_protected};
    let dir = data_dir.join("identity");
    std::fs::create_dir_all(&dir)?;
    restrict_dir(&dir)?;
    let path = dir.join("identity.json");
    let mut document: serde_json::Map<String, serde_json::Value> = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid public identity metadata")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(error) => return Err(error.into()),
    };
    let previous = document.clone();
    document.extend(wire::public_identity_proofs(
        identity,
        &pairing.box_transport_pubkey(),
    ));
    if let Some(endpoints) = endpoints {
        let mut descriptor = PairLink {
            v: wire::PAIR_LINK_VERSION,
            endpoint: endpoints[0].clone(),
            endpoints: endpoints.to_vec(),
            endpoints_signature: None,
            node_id: identity.node_id().to_hex(),
            transport_pubkey: hex::encode(identity.x25519_public().as_bytes()),
            transport_signature: String::new(),
            box_transport_pubkey: hex::encode(pairing.box_transport_pubkey()),
            box_transport_signature: None,
            code: String::new(),
            expires_at: 0,
            hosted_by: None,
        };
        descriptor.endpoints_signature = Some(
            URL_SAFE_NO_PAD.encode(
                identity
                    .sign(descriptor.endpoints_proof_message().as_bytes())
                    .to_bytes(),
            ),
        );
        document.insert("endpoints".into(), serde_json::to_value(endpoints)?);
        document.insert(
            "endpoints_signature".into(),
            descriptor.endpoints_signature.unwrap().into(),
        );
    }
    if document != previous {
        // Publish all fields together; a crash must not leave half a proof.
        let temporary = dir.join(format!(".identity-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            write_protected(&temporary, &serde_json::to_vec_pretty(&document)?)?;
            std::fs::rename(&temporary, &path)?;
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        result?;
    }
    // Retry synchronization even when the contents match: a prior start may
    // have failed after rename, and identity/ may itself be newly created.
    sync_dir(&dir)?;
    sync_dir(data_dir)?;
    crate::ticket_cmd::set_locked(&data_dir.join("pairing"), false)?;
    Ok(())
}

/// Public metadata signed on the last unlocked start. No seed or password.
#[derive(Clone, serde::Deserialize)]
pub struct LockedIdentity {
    pub node_id: String,
    pub identity_fingerprint: String,
    pub box_transport_pubkey: String,
    pub box_transport_signature: String,
}

#[derive(Clone)]
enum ResponderIdentity {
    Live(Arc<NodeIdentity>),
    Locked(Arc<LockedIdentity>),
    /// No identity exists yet: box static, pre-bootstrap tickets only.
    Bootstrap,
}

impl ResponderIdentity {
    /// The identity a ticket and pairing proof bind to; empty before bootstrap.
    fn ticket_node_id(&self) -> Option<String> {
        match self {
            Self::Live(identity) => Some(identity.node_id().to_hex()),
            Self::Bootstrap => Some(String::new()),
            Self::Locked(_) => None,
        }
    }
}

pub struct RemoteAccessServer {
    #[cfg(feature = "mdns")]
    _mdns: Option<crate::mdns::Advertisement>,
    listener: TcpListener,
    identity: ResponderIdentity,
    pairing: Arc<PairingService>,
    internal_api: SocketAddr,
    tunnel_clients: Arc<RemoteTunnelClients>,
    pairing_code: Arc<Mutex<Option<ActivePairingCode>>>,
    pair_link_path: Option<std::path::PathBuf>,
    pairing_deadline: Option<tokio::time::Instant>,
}

/// Wildcard IPv6 is explicitly dual-stack on every supported platform, so
/// endpoint discovery need not guess the OS IPV6_V6ONLY default.
async fn bind_remote_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        let socket = tokio::net::TcpSocket::new_v6()?;
        socket2::SockRef::from(&socket).set_only_v6(false)?;
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        socket.listen(1024)
    } else {
        TcpListener::bind(addr).await
    }
}

impl RemoteAccessServer {
    pub async fn bind(
        config: &RemoteAccessConfig,
        identity: Arc<NodeIdentity>,
        pairing: Arc<PairingService>,
        internal_api: SocketAddr,
        tunnel_clients: Arc<RemoteTunnelClients>,
    ) -> Result<Self> {
        let listen_addr = config
            .listen_addr
            .context("remote access is disabled (no listen_addr)")?;
        let listener = bind_remote_listener(listen_addr)
            .await
            .with_context(|| format!("could not bind remote access listener at {listen_addr}"))?;

        let endpoints = crate::endpoints::discover(config, listener.local_addr()?)?;
        write_identity_metadata_with_sync(
            pairing
                .remote_access_link_path()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
            &identity,
            &pairing,
            Some(&endpoints),
            konsensus_api::pairing::fsync_dir_strict,
        )?;
        let path = pairing.remote_access_link_path();
        let _guard = crate::ticket_cmd::lock_ticket(path.parent().unwrap())?;
        let mut pairing_code = None;
        if reload_pairing_code(&pairing, &mut pairing_code, &identity.node_id().to_hex()).is_err() {
            // A pre-bootstrap, replaced-identity or malformed ticket must not
            // prevent normal node startup. Never log its contents or parse error.
            pairing.remove_remote_access_link()?;
            warn!("discarded unusable remote pairing ticket at startup");
        }
        if pairing_code.is_none() && !path.exists() && pairing.pairing_open() {
            let node_id = identity.node_id().to_hex();
            let transport_pubkey = hex::encode(identity.x25519_public().as_bytes());
            let signature = URL_SAFE_NO_PAD.encode(
                identity
                    .sign(wire::transport_proof_message(&node_id, &transport_pubkey).as_bytes())
                    .to_bytes(),
            );
            let (box_transport_pubkey, box_transport_signature) =
                box_transport_proof(&identity, &pairing);
            let mut link = PairLink {
                v: wire::PAIR_LINK_VERSION,
                endpoint: endpoints[0].clone(),
                endpoints: endpoints.clone(),
                endpoints_signature: None,
                node_id,
                transport_pubkey,
                transport_signature: signature,
                box_transport_pubkey,
                box_transport_signature: Some(box_transport_signature),
                code: crate::ticket_cmd::new_code(),
                expires_at: chrono::Utc::now().timestamp() + PAIRING_CODE_TTL.as_secs() as i64,
                hosted_by: pairing.hosted_by().map(str::to_owned),
            };
            link.endpoints_signature = Some(
                URL_SAFE_NO_PAD.encode(
                    identity
                        .sign(link.endpoints_proof_message().as_bytes())
                        .to_bytes(),
                ),
            );
            pairing.write_remote_access_link(&link.to_uri()?)?;
            reload_pairing_code(&pairing, &mut pairing_code, &identity.node_id().to_hex())?;
        }
        let pairing_deadline = pairing_code.as_ref().map(|code| code.expires_at);
        let pair_link_path = pairing_code.as_ref().map(|_| path);

        Ok(Self {
            #[cfg(feature = "mdns")]
            _mdns: crate::mdns::Advertisement::start(config, listener.local_addr()?, &pairing),
            listener,
            identity: ResponderIdentity::Live(identity),
            pairing,
            internal_api,
            tunnel_clients,
            pairing_code: Arc::new(Mutex::new(pairing_code)),
            pair_link_path,
            pairing_deadline,
        })
    }

    /// Reuse the bounded tunnel, but with the box static and no first pairing.
    pub async fn bind_locked(
        config: &RemoteAccessConfig,
        identity: LockedIdentity,
        pairing: Arc<PairingService>,
        internal_api: SocketAddr,
        tunnel_clients: Arc<RemoteTunnelClients>,
    ) -> Result<Self> {
        anyhow::ensure!(!pairing.pairing_open(), "locked pairing must be closed");
        let listener = bind_remote_listener(
            config
                .listen_addr
                .context("remote unlock requires remote_access.listen_addr")?,
        )
        .await?;
        crate::ticket_cmd::set_locked(pairing.remote_access_link_path().parent().unwrap(), true)?;
        Ok(Self {
            #[cfg(feature = "mdns")]
            _mdns: crate::mdns::Advertisement::start(config, listener.local_addr()?, &pairing),
            listener,
            identity: ResponderIdentity::Locked(Arc::new(identity)),
            pairing,
            internal_api,
            tunnel_clients,
            pairing_code: Arc::new(Mutex::new(None)),
            pair_link_path: None,
            pairing_deadline: None,
        })
    }

    /// Pre-identity tunnel for remote first run: the box static, existing
    /// pairings, and first pairing only through a pre-bootstrap CLI ticket.
    /// Never mints a ticket itself; `konsensus pair-ticket` is the grant.
    pub async fn bind_bootstrap(
        config: &RemoteAccessConfig,
        pairing: Arc<PairingService>,
        internal_api: SocketAddr,
        tunnel_clients: Arc<RemoteTunnelClients>,
    ) -> Result<Self> {
        anyhow::ensure!(
            pairing.bound_fingerprint().is_empty(),
            "remote bootstrap requires an identity-free pairing state"
        );
        let listen_addr = config
            .listen_addr
            .context("remote bootstrap requires remote_access.listen_addr")?;
        let listener = bind_remote_listener(listen_addr)
            .await
            .with_context(|| format!("could not bind remote access listener at {listen_addr}"))?;
        let path = pairing.remote_access_link_path();
        let _guard = crate::ticket_cmd::lock_ticket(path.parent().unwrap())?;
        let mut pairing_code = None;
        if reload_pairing_code(&pairing, &mut pairing_code, "").is_err() {
            pairing.remove_remote_access_link()?;
            warn!("discarded unusable remote pairing ticket at bootstrap startup");
        }
        let pairing_deadline = pairing_code.as_ref().map(|code| code.expires_at);
        let pair_link_path = pairing_code.as_ref().map(|_| path);
        Ok(Self {
            #[cfg(feature = "mdns")]
            _mdns: crate::mdns::Advertisement::start(config, listener.local_addr()?, &pairing),
            listener,
            identity: ResponderIdentity::Bootstrap,
            pairing,
            internal_api,
            tunnel_clients,
            pairing_code: Arc::new(Mutex::new(pairing_code)),
            pair_link_path,
            pairing_deadline,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn pair_link_path(&self) -> Option<&std::path::Path> {
        self.pair_link_path.as_deref()
    }

    pub fn pairing_expires_in(&self) -> Option<Duration> {
        self.pairing_deadline
            .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()))
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        let limits = Arc::new(HandshakeLimiter::new());
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let refusal_slots = Arc::new(Semaphore::new(MAX_PENDING_REFUSALS));
        let mut tasks = tokio::task::JoinSet::new();

        let mut refresh = tokio::time::interval(Duration::from_secs(1));
        let ticket_node_id = self.identity.ticket_node_id();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = refresh.tick(), if ticket_node_id.is_some() => {
                    if let Some(node_id) = &ticket_node_id {
                        if refresh_pairing_code(&self.pairing, &self.pairing_code, node_id).is_err() {
                            warn!("could not reload remote pairing ticket");
                        }
                    }
                }
                accepted = self.listener.accept() => {
                    let (mut stream, peer_addr) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            warn!(%error, "remote access accept failed");
                            continue;
                        }
                    };
                    if let Err(retry_after) = limits.allow(peer_addr.ip(), Instant::now()) {
                        debug!(%peer_addr, "remote access pre-handshake rate limit");
                        // No Noise, identity or pairing work before this refusal.
                        // Slow readers cannot block accepts or create unbounded tasks.
                        if let Ok(permit) = Arc::clone(&refusal_slots).try_acquire_owned() {
                            tasks.spawn(async move {
                                let _permit = permit;
                                let _ = write_handshake_refusal(&mut stream, retry_after).await;
                            });
                        }
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                        debug!(%peer_addr, "remote access connection limit");
                        continue;
                    };
                    let identity = self.identity.clone();
                    let pairing = Arc::clone(&self.pairing);
                    let pairing_code = Arc::clone(&self.pairing_code);
                    let internal_api = self.internal_api;
                    let tunnel_clients = Arc::clone(&self.tunnel_clients);
                    let connection_shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(
                            stream,
                            identity,
                            pairing,
                            pairing_code,
                            internal_api,
                            tunnel_clients,
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

// Called only under the interprocess ticket lock. A missing/deleted file
// invalidates the cache; a digest and byte length detect atomic CLI replacement
// even with an unchanged mtime, without reparsing unchanged contents.
fn reload_pairing_code(
    pairing: &PairingService,
    active: &mut Option<ActivePairingCode>,
    node_id: &str,
) -> Result<()> {
    let path = pairing.remote_access_link_path();
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            *active = None;
            return Ok(());
        }
        Err(e) => {
            *active = None;
            return Err(e.into());
        }
    };
    let cached = active.take();
    anyhow::ensure!(
        metadata.len() <= 16 * 1024,
        "remote pairing ticket is too large"
    );
    let contents = std::fs::read_to_string(&path)?;
    let content_digest = blake3::hash(contents.as_bytes());
    let content_len = contents.len();
    if cached.as_ref().is_some_and(|code| {
        code.content_len == content_len && code.content_digest == content_digest
    }) {
        *active = cached;
        if active.as_ref().unwrap().expires_at <= tokio::time::Instant::now() {
            *active = None;
            pairing.remove_remote_access_link()?;
        }
        return Ok(());
    }
    let link = PairLink::from_uri(contents.trim())
        .map_err(|_| anyhow::anyhow!("invalid remote pairing ticket"))?;
    if link.expires_at <= chrono::Utc::now().timestamp() {
        pairing.remove_remote_access_link()?;
        return Ok(());
    }
    anyhow::ensure!(
        link.node_id == node_id
            && link.box_transport_pubkey == hex::encode(pairing.box_transport_pubkey()),
        "remote pairing ticket belongs to another identity"
    );
    anyhow::ensure!(
        URL_SAFE_NO_PAD
            .decode(&link.code)
            .is_ok_and(|code| code.len() == 32),
        "invalid ticket code"
    );
    let remaining =
        Duration::from_secs((link.expires_at - chrono::Utc::now().timestamp()).max(0) as u64);
    anyhow::ensure!(
        remaining <= Duration::from_secs(365 * 86400),
        "invalid ticket expiry"
    );
    *active = Some(ActivePairingCode {
        value: link.code,
        expires_at: tokio::time::Instant::now() + remaining,
        content_digest,
        content_len,
    });
    Ok(())
}

fn refresh_pairing_code(
    pairing: &PairingService,
    active: &Mutex<Option<ActivePairingCode>>,
    node_id: &str,
) -> Result<()> {
    let path = pairing.remote_access_link_path();
    let _guard = crate::ticket_cmd::lock_ticket(path.parent().unwrap())?;
    reload_pairing_code(
        pairing,
        &mut active.lock().unwrap_or_else(|e| e.into_inner()),
        node_id,
    )
}

fn authenticate_from_file(
    request: &AuthRequest,
    remote_static: &[u8; 32],
    node_id: &str,
    pairing: &PairingService,
    active: &Mutex<Option<ActivePairingCode>>,
) -> Result<PairedClient> {
    if request.code.is_none() {
        return authenticate(request, remote_static, node_id, pairing, active);
    }
    let path = pairing.remote_access_link_path();
    let _guard = crate::ticket_cmd::lock_ticket(path.parent().unwrap())?;
    reload_pairing_code(
        pairing,
        &mut active.lock().unwrap_or_else(|e| e.into_inner()),
        node_id,
    )?;
    authenticate(request, remote_static, node_id, pairing, active)
}

async fn handle_connection(
    stream: TcpStream,
    identity: ResponderIdentity,
    pairing: Arc<PairingService>,
    pairing_code: Arc<Mutex<Option<ActivePairingCode>>>,
    internal_api: SocketAddr,
    tunnel_clients: Arc<RemoteTunnelClients>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut authority_changes = pairing.subscribe_authority_changes();
    let (mut remote_reader, mut remote_writer) = stream.into_split();
    let handshake = async {
        // Migration: paired clients already pin this seed-derived static.
        // Advertise the identity-signed box key after auth; never rotate this
        // live responder before those clients have had a chance to learn it.
        let secret = match &identity {
            ResponderIdentity::Live(identity) => identity.x25519_secret_bytes(),
            ResponderIdentity::Locked(_) | ResponderIdentity::Bootstrap => {
                pairing.box_transport_secret_bytes()
            }
        };
        let mut noise = NoiseSession::responder(secret)?;
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

    let (authenticated, box_transport_pubkey, box_transport_signature) = match &identity {
        ResponderIdentity::Live(identity) => {
            let authenticated = authenticate_from_file(
                &request,
                &remote_static,
                &identity.node_id().to_hex(),
                &pairing,
                &pairing_code,
            );
            let (public, signature) = box_transport_proof(identity, &pairing);
            (authenticated, public, signature)
        }
        ResponderIdentity::Locked(identity) => {
            let authenticated = if request.code.is_some()
                || request.client_name.is_some()
                || request.client_pubkey.is_some()
                || request.signature.is_some()
            {
                Err(anyhow::anyhow!("first pairing is unavailable while locked"))
            } else {
                authenticate(
                    &request,
                    &remote_static,
                    &identity.node_id,
                    &pairing,
                    &pairing_code,
                )
            };
            (
                authenticated,
                identity.box_transport_pubkey.clone(),
                identity.box_transport_signature.clone(),
            )
        }
        // No identity can sign the box key yet: the ticket is the pin, and
        // finalize returns the committed identity's proof for re-pinning.
        ResponderIdentity::Bootstrap => (
            authenticate_from_file(&request, &remote_static, "", &pairing, &pairing_code),
            hex::encode(pairing.box_transport_pubkey()),
            String::new(),
        ),
    };
    let follow_rebind = matches!(identity, ResponderIdentity::Bootstrap);
    let response = match &authenticated {
        Ok(client) => AuthResponse::Ok {
            v: VERSION,
            client_id: client.client_id.clone(),
            scopes: client.scopes.clone(),
            box_transport_pubkey,
            box_transport_signature,
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
    validate_tunnel_authority(&pairing, &client, &remote_static, follow_rebind)?;

    let internal = TcpStream::connect(internal_api)
        .await
        .context("could not connect to internal remote API")?;
    // The server supplies the pairing, never an HTTP header. Registration must
    // precede the first forwarded byte so Axum can resolve every request.
    let _registration = tunnel_clients.register(internal.local_addr()?, client.client_id.clone());
    let (mut internal_reader, mut internal_writer) = internal.into_split();
    let mut internal_buf = zeroize::Zeroizing::new(vec![0u8; wire::MAX_TUNNEL_PLAINTEXT]);
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
            changed = authority_changes.changed() => {
                changed.context("pairing authority notification channel closed")?;
                validate_tunnel_authority(&pairing, &client, &remote_static, follow_rebind)?;
            }
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
                validate_tunnel_authority(&pairing, &client, &remote_static, follow_rebind)?;
                internal_writer.write_all(&plaintext).await?;
                internal_writer.flush().await?;
            }
            read = internal_reader.read(&mut internal_buf) => {
                let read = read?;
                if read == 0 {
                    return Ok(());
                }
                validate_tunnel_authority(&pairing, &client, &remote_static, follow_rebind)?;
                let ciphertext = wire::encode_transport(&mut noise, &internal_buf[..read])
                    .map_err(anyhow::Error::msg)?;
                wire::write_frame(&mut remote_writer, &ciphertext).await?;
            }
        }
    }
}

/// A bootstrap tunnel outlives the commit's rebind from the empty fingerprint
/// so finalize can answer; revocation or an epoch change still closes it, and
/// the committed bootstrap router refuses every ceremony call.
fn validate_tunnel_authority(
    pairing: &PairingService,
    client: &PairedClient,
    remote_static: &[u8; 32],
    follow_rebind: bool,
) -> Result<()> {
    let fingerprint = if follow_rebind {
        pairing.bound_fingerprint()
    } else {
        client.identity_fingerprint.clone()
    };
    pairing
        .validate_remote_authority(&client.client_id, client.epoch, remote_static, &fingerprint)
        .map_err(anyhow::Error::from)
}

fn authenticate(
    request: &AuthRequest,
    remote_static: &[u8; 32],
    node_id: &str,
    pairing: &PairingService,
    pairing_code: &Mutex<Option<ActivePairingCode>>,
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
    let active = code_guard
        .as_ref()
        .context("first-pairing code is unavailable or already used")?;
    if tokio::time::Instant::now() >= active.expires_at {
        *code_guard = None;
        pairing
            .remove_remote_access_link()
            .context("could not remove expired remote pairing link")?;
        anyhow::bail!("first-pairing code expired");
    }
    if blake3::hash(code.as_bytes()) != blake3::hash(active.value.as_bytes()) {
        anyhow::bail!("pairing code did not match");
    }

    *code_guard = None;
    pairing
        .remove_remote_access_link()
        .context("could not remove consumed remote pairing link")?;
    // `node_id` is server state: empty only on the identity-free bootstrap
    // responder, where the pairing service also refuses once one is bound.
    let client = if node_id.is_empty() {
        pairing.create_bootstrap_ticket_pairing(name, pubkey_hex, remote_static)
    } else {
        pairing.create_ticket_remote_pairing(name, pubkey_hex, remote_static)
    }
    .map_err(anyhow::Error::from)?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Client fixture: use the already trusted node_id, not an identity supplied
    // by the response. Only a verified proof can become a durable box pin.
    fn verified_box_pin(node_id: &str, public_key: &str, signature: &str) -> Result<[u8; 32]> {
        let identity_bytes: [u8; 32] = hex::decode(node_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("identity length"))?;
        let key: [u8; 32] = hex::decode(public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("box key length"))?;
        let signature = ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature)?)?;
        let message = format!("bitsov-box-transport-v1:{node_id}:{public_key}");
        ed25519_dalek::VerifyingKey::from_bytes(&identity_bytes)?
            .verify_strict(message.as_bytes(), &signature)?;
        Ok(key)
    }

    #[tokio::test]
    async fn ticket_survives_listener_restart() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = Arc::new(PairingService::open(dir.path(), fingerprint, false).unwrap());
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let bind = || {
            RemoteAccessServer::bind(
                &config,
                node.clone(),
                pairing.clone(),
                "127.0.0.1:1".parse().unwrap(),
                Arc::new(RemoteTunnelClients::default()),
            )
        };
        let server = bind().await.unwrap();
        let path = server.pair_link_path().unwrap().to_path_buf();
        let original = std::fs::read_to_string(&path).unwrap();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(server.serve(rx));
        tx.send(true).unwrap();
        task.await.unwrap();
        let _restarted = bind().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            original,
            "an unused ticket must survive clean shutdown and restart"
        );
    }

    #[tokio::test]
    async fn ticket_reload_revokes_old_code_when_replacement_has_same_mtime_and_length() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let node_id = node.node_id().to_hex();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node_id);
        let pairing = Arc::new(PairingService::open(dir.path(), fingerprint, false).unwrap());
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let path = pairing.remote_access_link_path();
        let mut ticket = PairLink::from_uri(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let old_code = ticket.code.clone();
        let metadata = std::fs::metadata(&path).unwrap();
        let modified = metadata.modified().unwrap();
        ticket.code = URL_SAFE_NO_PAD.encode([0x42; 32]);
        if ticket.code == old_code {
            ticket.code = URL_SAFE_NO_PAD.encode([0x43; 32]);
        }
        {
            let _guard = crate::ticket_cmd::lock_ticket(path.parent().unwrap()).unwrap();
            pairing
                .write_remote_access_link(&ticket.to_uri().unwrap())
                .unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(modified)
                .unwrap();
        }
        let replacement = std::fs::metadata(&path).unwrap();
        assert_eq!(replacement.modified().unwrap(), modified);
        assert_eq!(replacement.len(), metadata.len());

        let transport = [0x18; 32];
        let key = SigningKey::from_bytes(&[0x28; 32]);
        assert!(authenticate_from_file(
            &request(&node, &transport, &old_code, &key),
            &transport,
            &node_id,
            &pairing,
            &server.pairing_code,
        )
        .is_err());
        assert!(authenticate_from_file(
            &request(&node, &transport, &ticket.code, &key),
            &transport,
            &node_id,
            &pairing,
            &server.pairing_code,
        )
        .is_ok());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn ticket_reload_honors_ttl_and_is_single_use_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing =
            Arc::new(PairingService::open(dir.path(), fingerprint.clone(), false).unwrap());
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let path = pairing.remote_access_link_path();
        let mut ticket = PairLink::from_uri(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let old_code = ticket.code.clone();
        ticket.code = crate::ticket_cmd::new_code();
        ticket.expires_at = chrono::Utc::now().timestamp() + 3600;
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        let key = SigningKey::from_bytes(&[0x28; 32]);
        assert!(authenticate_from_file(
            &request(&node, &[0x18; 32], &old_code, &key),
            &[0x18; 32],
            &node.node_id().to_hex(),
            &pairing,
            &server.pairing_code
        )
        .is_err());
        assert!(
            server
                .pairing_code
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .expires_at
                .duration_since(tokio::time::Instant::now())
                > Duration::from_secs(3500)
        );
        drop(server);
        drop(pairing);
        let pairing =
            Arc::new(PairingService::open(dir.path(), fingerprint.clone(), false).unwrap());
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let auth = request(&node, &[0x18; 32], &ticket.code, &key);
        let client = authenticate_from_file(
            &auth,
            &[0x18; 32],
            &node.node_id().to_hex(),
            &pairing,
            &server.pairing_code,
        )
        .unwrap();
        assert_eq!(
            client.scopes,
            vec![
                konsensus_api::auth::Scope::Read,
                konsensus_api::auth::Scope::Receive
            ]
        );
        assert!(!path.exists());
        drop(server);
        drop(pairing);
        let pairing = Arc::new(PairingService::open(dir.path(), fingerprint, false).unwrap());
        assert!(!pairing.pairing_open());
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        assert!(authenticate_from_file(
            &request(
                &node,
                &[0x19; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x29; 32])
            ),
            &[0x19; 32],
            &node.node_id().to_hex(),
            &pairing,
            &server.pairing_code
        )
        .is_err());
        // The exact durable pairing may retry a lost response.
        assert!(authenticate_from_file(
            &auth,
            &[0x18; 32],
            &node.node_id().to_hex(),
            &pairing,
            &server.pairing_code
        )
        .is_ok());
        // A CLI ticket pairs a second device without owner control.
        ticket.code = crate::ticket_cmd::new_code();
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        assert!(authenticate_from_file(
            &request(
                &node,
                &[0x19; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x29; 32])
            ),
            &[0x19; 32],
            &node.node_id().to_hex(),
            &pairing,
            &server.pairing_code
        )
        .is_ok());
        // A persisted absolute expiry is checked even with a fresh empty cache.
        ticket.code = crate::ticket_cmd::new_code();
        ticket.expires_at = chrono::Utc::now().timestamp() - 1;
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        assert!(authenticate_from_file(
            &request(
                &node,
                &[0x20; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x30; 32])
            ),
            &[0x20; 32],
            &node.node_id().to_hex(),
            &pairing,
            &Mutex::new(None)
        )
        .is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn stale_or_prebootstrap_ticket_cannot_block_live_startup() {
        for stale in ["prebootstrap", "other-identity", "malformed"] {
            let dir = tempfile::tempdir().unwrap();
            let node = identity();
            let pairing = Arc::new(
                PairingService::open(
                    dir.path(),
                    konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex()),
                    false,
                )
                .unwrap(),
            );
            let config = RemoteAccessConfig {
                listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                advertised_endpoint: Some("node.example:8443".into()),
                ..Default::default()
            };
            let bind = || {
                RemoteAccessServer::bind(
                    &config,
                    node.clone(),
                    pairing.clone(),
                    "127.0.0.1:1".parse().unwrap(),
                    Arc::new(RemoteTunnelClients::default()),
                )
            };
            let server = bind().await.unwrap();
            let path = pairing.remote_access_link_path();
            let mut link = PairLink::from_uri(&std::fs::read_to_string(&path).unwrap()).unwrap();
            drop(server);
            let old_code = link.code.clone();
            link.node_id = if stale == "prebootstrap" {
                String::new()
            } else {
                "00".repeat(32)
            };
            let uri = if stale == "malformed" {
                "broken ticket".into()
            } else {
                link.to_uri().unwrap()
            };
            pairing.write_remote_access_link(&uri).unwrap();
            let _live = bind()
                .await
                .expect("unusable ticket must not block normal startup");
            let fresh = PairLink::from_uri(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(fresh.node_id, node.node_id().to_hex());
            assert_ne!(fresh.code, old_code);
        }
    }

    #[tokio::test]
    async fn tickets_never_open_the_local_pair_request_window() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let node_id = node.node_id().to_hex();
        let pairing = Arc::new(
            PairingService::open(
                dir.path(),
                konsensus_api::pairing::identity_fingerprint(&node_id),
                false,
            )
            .unwrap(),
        );
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let local_request = || {
            let key = SigningKey::from_bytes(&[0x50; 32]);
            pairing.request_pairing("local", &hex::encode(key.verifying_key().to_bytes()))
        };
        let path = pairing.remote_access_link_path();
        let mut ticket = PairLink::from_uri(&std::fs::read_to_string(&path).unwrap()).unwrap();

        // Consuming the first-run ticket leaves /pair/request closed, as on a
        // node whose first client paired locally.
        authenticate_from_file(
            &request(
                &node,
                &[0x41; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x41; 32]),
            ),
            &[0x41; 32],
            &node_id,
            &pairing,
            &server.pairing_code,
        )
        .unwrap();
        assert!(!pairing.pairing_open());
        assert!(matches!(
            local_request(),
            Err(konsensus_api::pairing::PairingError::Closed)
        ));

        // A long-lived operator ticket stays pending without opening the window.
        ticket.code = crate::ticket_cmd::new_code();
        ticket.expires_at = chrono::Utc::now().timestamp() + 365 * 86400;
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        refresh_pairing_code(&pairing, &server.pairing_code, &node_id).unwrap();
        assert!(server.pairing_code.lock().unwrap().is_some());
        assert!(!pairing.pairing_open());
        assert!(matches!(
            local_request(),
            Err(konsensus_api::pairing::PairingError::Closed)
        ));

        // The ticket itself is the grant: it pairs a second device anyway.
        let second = authenticate_from_file(
            &request(
                &node,
                &[0x42; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x42; 32]),
            ),
            &[0x42; 32],
            &node_id,
            &pairing,
            &server.pairing_code,
        )
        .unwrap();
        assert_eq!(
            second.scopes,
            vec![
                konsensus_api::auth::Scope::Read,
                konsensus_api::auth::Scope::Receive
            ]
        );
        assert!(!path.exists());
        assert!(!pairing.pairing_open());
        assert!(matches!(
            local_request(),
            Err(konsensus_api::pairing::PairingError::Closed)
        ));

        // The legacy verified-remote entry point still honours the window.
        assert!(matches!(
            pairing.create_verified_remote_pairing(
                "windowless",
                &hex::encode(
                    SigningKey::from_bytes(&[0x43; 32])
                        .verifying_key()
                        .to_bytes()
                ),
                &[0x43; 32],
            ),
            Err(konsensus_api::pairing::PairingError::Closed)
        ));
    }

    #[tokio::test]
    async fn bootstrap_ticket_pairs_one_identity_client_without_local_window() {
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let bind = |pairing| {
            RemoteAccessServer::bind_bootstrap(
                &config,
                pairing,
                "127.0.0.1:1".parse().unwrap(),
                Arc::new(RemoteTunnelClients::default()),
            )
        };
        let live = tempfile::tempdir().unwrap();
        let bound = Arc::new(PairingService::open(live.path(), "ab".repeat(32), false).unwrap());
        assert!(bind(bound).await.is_err());

        let dir = tempfile::tempdir().unwrap();
        let pairing = Arc::new(PairingService::open(dir.path(), String::new(), false).unwrap());
        let mut ticket = PairLink {
            v: VERSION,
            endpoint: "node.example:8443".into(),
            endpoints: vec![],
            endpoints_signature: None,
            node_id: String::new(),
            transport_pubkey: String::new(),
            transport_signature: String::new(),
            box_transport_pubkey: hex::encode(pairing.box_transport_pubkey()),
            box_transport_signature: None,
            code: crate::ticket_cmd::new_code(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
            hosted_by: None,
        };
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        let server = bind(pairing.clone()).await.unwrap();
        assert_eq!(server.identity.ticket_node_id().as_deref(), Some(""));
        let bootstrap_request = |transport: &[u8; 32], code: &str, key: &SigningKey| {
            let pubkey = hex::encode(key.verifying_key().to_bytes());
            let proof = wire::pairing_proof_message("", &hex::encode(transport), code, &pubkey);
            AuthRequest {
                v: VERSION,
                code: Some(code.into()),
                client_name: Some("phone".into()),
                client_pubkey: Some(pubkey),
                signature: Some(URL_SAFE_NO_PAD.encode(key.sign(proof.as_bytes()).to_bytes())),
            }
        };

        // A proof bound to some identity is not a pre-bootstrap proof.
        assert!(authenticate_from_file(
            &request(
                &identity(),
                &[0x61; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x61; 32])
            ),
            &[0x61; 32],
            "",
            &pairing,
            &server.pairing_code,
        )
        .is_err());
        let first = authenticate_from_file(
            &bootstrap_request(
                &[0x62; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x62; 32]),
            ),
            &[0x62; 32],
            "",
            &pairing,
            &server.pairing_code,
        )
        .unwrap();
        assert_eq!(
            first.scopes,
            konsensus_api::pairing::bootstrap_pairing_scopes()
        );
        assert!(first.identity_fingerprint.is_empty());
        assert!(!pairing.remote_access_link_path().exists());
        assert!(!pairing.pairing_open());
        assert!(matches!(
            pairing.request_pairing(
                "local",
                &hex::encode(
                    SigningKey::from_bytes(&[0x63; 32])
                        .verifying_key()
                        .to_bytes()
                )
            ),
            Err(konsensus_api::pairing::PairingError::Closed)
        ));

        // Only one first-run client: a second ticket cannot add another.
        ticket.code = crate::ticket_cmd::new_code();
        pairing
            .write_remote_access_link(&ticket.to_uri().unwrap())
            .unwrap();
        assert!(authenticate_from_file(
            &bootstrap_request(
                &[0x64; 32],
                &ticket.code,
                &SigningKey::from_bytes(&[0x64; 32])
            ),
            &[0x64; 32],
            "",
            &pairing,
            &server.pairing_code,
        )
        .is_err());
        assert_eq!(pairing.list_clients().len(), 1);
    }

    #[tokio::test]
    async fn ticket_concurrent_consumers_create_only_one_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let pairing = Arc::new(
            PairingService::open(
                dir.path(),
                konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex()),
                false,
            )
            .unwrap(),
        );
        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:8443".into()),
            ..Default::default()
        };
        let server = RemoteAccessServer::bind(
            &config,
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let ticket = PairLink::from_uri(
            &std::fs::read_to_string(pairing.remote_access_link_path()).unwrap(),
        )
        .unwrap();
        let barrier = std::sync::Barrier::new(2);
        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = [0x31u8, 0x32]
                .into_iter()
                .map(|n| {
                    let node = &node;
                    let pairing = &pairing;
                    let ticket = &ticket;
                    let barrier = &barrier;
                    let cache = &server.pairing_code;
                    scope.spawn(move || {
                        barrier.wait();
                        authenticate_from_file(
                            &request(
                                node,
                                &[n; 32],
                                &ticket.code,
                                &SigningKey::from_bytes(&[n; 32]),
                            ),
                            &[n; 32],
                            &node.node_id().to_hex(),
                            pairing,
                            cache,
                        )
                        .is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 1);
        assert!(!pairing.remote_access_link_path().exists());
    }

    #[test]
    fn box_identity_metadata_is_created_refreshed_and_preserves_bootstrap_fields() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = PairingService::open(dir.path(), fingerprint.clone(), false).unwrap();
        write_identity_metadata(dir.path(), &node, &pairing).unwrap();
        let path = dir.path().join("identity/identity.json");
        let read =
            || serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap();
        let document = read();
        assert_eq!(document["node_id"], node.node_id().to_hex());
        assert_eq!(document["identity_fingerprint"], fingerprint);
        let public_key = document["box_transport_pubkey"].as_str().unwrap();
        let signature = document["box_transport_signature"].as_str().unwrap();
        assert_eq!(
            verified_box_pin(&node.node_id().to_hex(), public_key, signature).unwrap(),
            pairing.box_transport_pubkey()
        );
        assert_ne!(public_key, hex::encode(node.x25519_public().as_bytes()));
        assert!(verified_box_pin(&identity().node_id().to_hex(), public_key, signature).is_err());
        assert!(verified_box_pin(&node.node_id().to_hex(), &"00".repeat(32), signature).is_err());
        assert!(verified_box_pin(
            &node.node_id().to_hex(),
            public_key,
            &URL_SAFE_NO_PAD.encode([0u8; 64])
        )
        .is_err());
        // Old bootstrap documents had no node_id or box proof. Keep their
        // audit timestamp when adding the new public fields on live startup.
        std::fs::write(
            &path,
            r#"{"identity_fingerprint":"stale","committed_at":123}"#,
        )
        .unwrap();
        drop(pairing);
        let restarted = PairingService::open(dir.path(), fingerprint, false).unwrap();
        write_identity_metadata(dir.path(), &node, &restarted).unwrap();
        let refreshed = read();
        assert_eq!(refreshed["committed_at"], 123);
        for field in [
            "node_id",
            "identity_fingerprint",
            "box_transport_pubkey",
            "box_transport_signature",
        ] {
            assert_eq!(refreshed[field], document[field]);
        }
        // Unreadable metadata is an error, not permission to erase evidence.
        std::fs::write(&path, b"broken").unwrap();
        assert!(write_identity_metadata(dir.path(), &node, &restarted).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"broken");
    }

    #[test]
    fn box_metadata_directory_sync_failure_refuses_start_even_when_unchanged() {
        for existing in [false, true] {
            for fail_parent in [false, true] {
                let data = tempfile::tempdir().unwrap();
                let node = identity();
                let pairing = PairingService::open(data.path(), String::new(), false).unwrap();
                if existing {
                    write_identity_metadata(data.path(), &node, &pairing).unwrap();
                }
                let dir = data.path().join("identity");
                let failed_path = if fail_parent { data.path() } else { &dir };
                let result =
                    write_identity_metadata_with_sync(data.path(), &node, &pairing, None, |path| {
                        if path == failed_path {
                            Err(std::io::Error::other("injected directory sync failure"))
                        } else {
                            konsensus_api::pairing::fsync_dir(path)
                        }
                    });
                assert!(result.is_err(), "existing={existing}, parent={fail_parent}");
                let path = dir.join("identity.json");
                let before = std::fs::read(&path).unwrap();
                write_identity_metadata(data.path(), &node, &pairing).unwrap();
                assert_eq!(std::fs::read(path).unwrap(), before);
            }
        }
    }

    #[test]
    fn handshake_burst_is_limited_then_recovers_without_restarting() {
        let limiter = HandshakeLimiter::new();
        let ip = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..20 {
            assert!(limiter.allow(ip, now).is_ok());
        }
        for _ in 0..1000 {
            assert!(limiter.allow(ip, now + Duration::from_secs(1)).is_err());
        }
        // Rejected attempts cannot extend the debt; backing off restores the
        // full burst budget within one minute, without replacing the limiter.
        for _ in 0..20 {
            assert!(limiter.allow(ip, now + Duration::from_secs(60)).is_ok());
        }
        assert!(limiter.allow(ip, now + Duration::from_secs(60)).is_err());
    }

    #[test]
    fn handshake_penalty_decays_gradually_and_ips_are_independent() {
        let limiter = HandshakeLimiter::new();
        let ip = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..20 {
            assert!(limiter.allow(ip, now).is_ok());
        }
        assert!(limiter
            .allow(ip, now + Duration::from_millis(2999))
            .is_err());
        assert!(limiter.allow("192.0.2.2".parse().unwrap(), now).is_ok());
        // Twenty handshakes/minute replenish one admission every 3 seconds.
        assert!(limiter.allow(ip, now + Duration::from_secs(3)).is_ok());
        assert!(limiter.allow(ip, now + Duration::from_secs(3)).is_err());
        for _ in 0..2 {
            assert!(limiter.allow(ip, now + Duration::from_secs(9)).is_ok());
        }
        assert!(limiter.allow(ip, now + Duration::from_secs(9)).is_err());
    }

    #[test]
    fn handshake_ip_table_stays_bounded_and_recovers_after_debt_drains() {
        let limiter = HandshakeLimiter::new();
        let now = Instant::now();
        for n in 0..MAX_RATE_LIMIT_IPS as u32 {
            assert!(limiter.allow(IpAddr::V4(n.into()), now).is_ok());
        }
        let new_ip = "192.0.2.1".parse().unwrap();
        assert_eq!(limiter.allow(new_ip, now), Err(Duration::from_secs(3)));
        assert_eq!(limiter.entries.lock().unwrap().len(), MAX_RATE_LIMIT_IPS);
        // A full table must still apply the existing IP's remaining budget.
        let tracked = IpAddr::V4(0.into());
        for _ in 0..19 {
            assert!(limiter.allow(tracked, now).is_ok());
        }
        assert_eq!(limiter.allow(tracked, now), Err(Duration::from_secs(3)));
        assert_eq!(
            limiter.allow(new_ip, now + Duration::from_millis(2999)),
            Err(Duration::from_millis(1))
        );
        assert!(limiter.allow(new_ip, now + Duration::from_secs(3)).is_ok());
        assert_eq!(limiter.entries.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn handshake_refusal_carries_only_retry_hint_and_honoring_it_recovers() {
        let limiter = HandshakeLimiter::new();
        let ip = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..20 {
            limiter.allow(ip, now).unwrap();
        }
        for (elapsed_ms, expected_secs) in [(0, 3), (1000, 2), (2999, 1)] {
            let retry_after = limiter
                .allow(ip, now + Duration::from_millis(elapsed_ms))
                .unwrap_err();
            let (mut server, mut client) = tokio::io::duplex(256);
            wire::write_frame(&mut client, &[0; 32]).await.unwrap();
            write_handshake_refusal(&mut server, retry_after)
                .await
                .unwrap();
            // Decode the actual outer frame that the app receives before Noise.
            let bytes = wire::read_frame(&mut client, 256).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                json,
                serde_json::json!({
                    "v": 1, "code": "rate_limited", "retry_after_secs": expected_secs
                })
            );
            assert_eq!(
                client.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
        assert!(limiter.allow(ip, now + Duration::from_secs(3)).is_ok());
        assert!(limiter.allow(ip, now + Duration::from_secs(3)).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_refusal_does_not_wait_forever_for_a_slow_reader() {
        let (mut server, _client) = tokio::io::duplex(1);
        let start = tokio::time::Instant::now();
        let result = write_handshake_refusal(&mut server, Duration::from_secs(3)).await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn handshake_refusal_allows_client_to_finish_first_frame() {
        let (mut server, mut client) = tokio::io::duplex(256);
        client.write_u32(32).await.unwrap();
        let refusal = tokio::spawn(async move {
            write_handshake_refusal(&mut server, Duration::from_secs(3)).await
        });
        let bytes = wire::read_frame(&mut client, 256).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["retry_after_secs"],
            3
        );
        // A real TCP client can send the length and body in separate packets.
        // Closing before the body arrives can reset its write and lose the hint.
        client.write_all(&[0; 32]).await.unwrap();
        refusal.await.unwrap().unwrap();
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_refusal_bounds_wait_for_incomplete_first_frame() {
        let (mut server, mut client) = tokio::io::duplex(256);
        client.write_u32(32).await.unwrap();
        let start = tokio::time::Instant::now();
        let refusal = tokio::spawn(async move {
            write_handshake_refusal(&mut server, Duration::from_secs(3)).await
        });
        let bytes = wire::read_frame(&mut client, 256).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "rate_limited"
        );
        assert!(refusal
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    fn active_code(value: &str) -> Mutex<Option<ActivePairingCode>> {
        Mutex::new(Some(ActivePairingCode {
            value: value.to_string(),
            expires_at: tokio::time::Instant::now() + PAIRING_CODE_TTL,
            content_digest: blake3::hash(value.as_bytes()),
            content_len: value.len(),
        }))
    }

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
        let code = active_code("correct-code");
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

    #[tokio::test(start_paused = true)]
    async fn expired_pairing_code_is_rejected_cleared_and_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = PairingService::open(dir.path(), fingerprint, false).unwrap();
        let link_path = pairing.write_remote_access_link("secret-link").unwrap();
        let code = active_code("short-lived");
        let transport = [0x31u8; 32];
        let key = SigningKey::from_bytes(&[0x32u8; 32]);

        tokio::time::advance(PAIRING_CODE_TTL).await;
        let error = authenticate(
            &request(&node, &transport, "short-lived", &key),
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code,
        )
        .unwrap_err();

        assert!(error.to_string().contains("expired"));
        assert!(code.lock().unwrap().is_none());
        assert!(!link_path.exists());
    }

    #[test]
    fn epoch_and_client_key_rotation_invalidate_captured_remote_authority() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = PairingService::open(dir.path(), fingerprint, false).unwrap();
        let code = active_code("rotate-code");
        let transport = [0x41u8; 32];
        let old_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let paired = authenticate(
            &request(&node, &transport, "rotate-code", &old_key),
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code,
        )
        .unwrap();
        let mut changes = pairing.subscribe_authority_changes();
        pairing
            .validate_remote_authority(
                &paired.client_id,
                paired.epoch,
                &transport,
                &paired.identity_fingerprint,
            )
            .unwrap();

        pairing.bump_epoch(&paired.client_id).unwrap();
        assert!(changes.has_changed().unwrap());
        assert!(pairing
            .validate_remote_authority(
                &paired.client_id,
                paired.epoch,
                &transport,
                &paired.identity_fingerprint,
            )
            .is_err());
        changes.borrow_and_update();

        let new_key = SigningKey::from_bytes(&[0x43u8; 32]);
        let new_pubkey = hex::encode(new_key.verifying_key().to_bytes());
        let proof = format!("bitsov-pair-rotate-v1:{}:{}", paired.client_id, new_pubkey);
        let rotated = pairing
            .rotate_client_key(
                &paired.client_id,
                &new_pubkey,
                &hex::encode(old_key.sign(proof.as_bytes()).to_bytes()),
            )
            .unwrap();
        assert!(changes.has_changed().unwrap());
        assert!(rotated.remote_transport_pubkey.is_none());
        assert!(
            pairing.validate_remote_transport(&transport).is_err(),
            "the old X25519 static must fail immediately after client-key rotation"
        );
    }

    #[test]
    fn later_repair_of_same_keys_does_not_revive_captured_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex());
        let pairing = PairingService::open(dir.path(), fingerprint, false).unwrap();
        let code = active_code("repair-code");
        let transport = [0x61u8; 32];
        let key = SigningKey::from_bytes(&[0x62u8; 32]);
        let captured = authenticate(
            &request(&node, &transport, "repair-code", &key),
            &transport,
            &node.node_id().to_hex(),
            &pairing,
            &code,
        )
        .unwrap();

        pairing.revoke(&captured.client_id).unwrap();
        let repaired = pairing
            .create_verified_remote_pairing("remote test", &captured.client_pubkey, &transport)
            .unwrap();
        assert!(repaired.epoch > captured.epoch);
        assert!(pairing
            .validate_remote_authority(
                &captured.client_id,
                captured.epoch,
                &transport,
                &captured.identity_fingerprint,
            )
            .is_err());
        pairing
            .validate_remote_authority(
                &repaired.client_id,
                repaired.epoch,
                &transport,
                &repaired.identity_fingerprint,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_paired_client_reconnects_and_learns_box_pin_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let node_id = node.node_id().to_hex();
        let fingerprint = konsensus_api::pairing::identity_fingerprint(&node_id);
        let client_secret = [0x63; 32];
        let client_static = X25519PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();
        let legacy = PairingService::open(dir.path(), fingerprint.clone(), false).unwrap();
        let client = legacy
            .create_verified_remote_pairing(
                "legacy app",
                &hex::encode(
                    SigningKey::from_bytes(&[0x64; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                &client_static,
            )
            .unwrap();
        drop(legacy);
        // A pre-U1 data directory has pairings but no box key. The client has
        // only the old seed-derived responder pin, with no new pairing ticket.
        std::fs::remove_file(dir.path().join("pairing/box-transport.key")).unwrap();
        let legacy_pin = *node.x25519_public().as_bytes();
        let mut saved_box_pin = None;
        for _ in 0..2 {
            let pairing =
                Arc::new(PairingService::open(dir.path(), fingerprint.clone(), false).unwrap());
            assert!(!pairing.pairing_open());
            write_identity_metadata(dir.path(), &node, &pairing).unwrap();
            let internal = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = RemoteAccessServer::bind(
                &RemoteAccessConfig {
                    listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                    advertised_endpoint: Some("node.example:18443".into()),
                    ..Default::default()
                },
                Arc::clone(&node),
                Arc::clone(&pairing),
                internal.local_addr().unwrap(),
                Arc::new(RemoteTunnelClients::default()),
            )
            .await
            .unwrap();
            assert!(server.pair_link_path().is_none());
            let address = server.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let task = tokio::spawn(server.serve(shutdown_rx));
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut noise = NoiseSession::initiator(&client_secret).unwrap();
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
            assert_eq!(noise.remote_static_key().unwrap(), &legacy_pin);
            wire::write_frame(&mut stream, &noise.write_handshake(&[]).unwrap())
                .await
                .unwrap();
            noise.try_finish_handshake().unwrap();
            let auth = br#"{"v":1}"#;
            wire::write_frame(
                &mut stream,
                &wire::encode_transport(&mut noise, auth).unwrap(),
            )
            .await
            .unwrap();
            let ciphertext = wire::read_frame(&mut stream, wire::MAX_TRANSPORT_FRAME)
                .await
                .unwrap();
            let plaintext =
                wire::decode_transport(&mut noise, &ciphertext, wire::MAX_AUTH_PLAINTEXT).unwrap();
            // Today's response decoder ignores additive fields. Preserve that
            // wire compatibility as well as the old responder static.
            #[derive(serde::Deserialize)]
            struct LegacyResponse {
                status: String,
                v: u8,
                client_id: String,
                scopes: Vec<konsensus_api::auth::Scope>,
            }
            let old_response: LegacyResponse = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(old_response.status, "ok");
            assert_eq!(old_response.v, VERSION);
            assert_eq!(old_response.client_id, client.client_id);
            assert_eq!(old_response.scopes, client.scopes);
            let response: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
            let public_key = response["box_transport_pubkey"].as_str().unwrap();
            let signature = response["box_transport_signature"].as_str().unwrap();
            let pin = verified_box_pin(&node_id, public_key, signature).unwrap();
            assert_ne!(pin, legacy_pin);
            assert_eq!(pin, pairing.box_transport_pubkey());
            let document: serde_json::Value = serde_json::from_slice(
                &std::fs::read(dir.path().join("identity/identity.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(document["box_transport_pubkey"], public_key);
            assert_eq!(document["box_transport_signature"], signature);
            if let Some(saved) = saved_box_pin {
                assert_eq!(pin, saved);
            }
            saved_box_pin = Some(pin);
            assert_eq!(
                pairing
                    .validate_remote_transport(&client_static)
                    .unwrap()
                    .epoch,
                client.epoch
            );
            shutdown_tx.send(true).unwrap();
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn ipv6_wildcard_listener_accepts_ipv4() {
        let listener = bind_remote_listener("[::]:0".parse().unwrap())
            .await
            .unwrap();
        assert!(!socket2::SockRef::from(&listener).only_v6().unwrap());
        let target = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(target))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cli_reuses_signed_endpoint_metadata_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let node = identity();
        let pairing = Arc::new(
            PairingService::open(
                dir.path(),
                konsensus_api::pairing::identity_fingerprint(&node.node_id().to_hex()),
                false,
            )
            .unwrap(),
        );
        let server = RemoteAccessServer::bind(
            &RemoteAccessConfig {
                listen_addr: Some("127.0.0.1:0".parse().unwrap()),
                advertised_endpoint: Some("node.example:9737".into()),
                ..Default::default()
            },
            node.clone(),
            pairing.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        #[cfg(feature = "mdns")]
        assert!(
            server._mdns.is_none(),
            "ordinary listeners must not start mDNS"
        );
        let automatic = PairLink::from_uri(
            &std::fs::read_to_string(pairing.remote_access_link_path()).unwrap(),
        )
        .unwrap();
        assert_eq!(automatic.v, wire::PAIR_LINK_VERSION);
        automatic
            .verify_endpoints(&node.node_id().to_hex())
            .unwrap();
        assert_eq!(
            automatic.endpoints,
            [
                "node.example:9737".to_string(),
                server.local_addr().unwrap().to_string()
            ]
        );
        let mut config = crate::config::NodeConfig::default_for_tier(
            crate::config::NodeTier::Light,
            dir.path().join("absent.enc"),
            dir.path(),
        );
        config.remote_access = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:9737".into()),
            ..Default::default()
        };
        let path = dir.path().join("konsensus.toml");
        config.save(&path).unwrap();
        crate::ticket_cmd::cmd_pair_ticket(&path, false, Duration::from_secs(60), false).unwrap();
        let uri = std::fs::read_to_string(pairing.remote_access_link_path()).unwrap();
        let link = PairLink::from_uri(&uri).unwrap();
        link.verify_endpoints(&node.node_id().to_hex()).unwrap();
        assert_eq!(link.endpoints, automatic.endpoints);
        assert_ne!(link.code, automatic.code);
        assert!(
            !config.identity.mnemonic_file.exists(),
            "CLI must need no seed"
        );
        // Corrupt one cached signature byte. The existing grant must survive.
        let metadata = dir.path().join("identity/identity.json");
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
        document["endpoints_signature"] = URL_SAFE_NO_PAD.encode([0; 64]).into();
        std::fs::write(metadata, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(
            crate::ticket_cmd::cmd_pair_ticket(&path, false, Duration::from_secs(60), false)
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(pairing.remote_access_link_path()).unwrap(),
            uri
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
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nsafe")
                .await
                .unwrap();
            let mut unexpected = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut unexpected))
                .await
                .expect("revoked tunnel should promptly close its internal connection")
                .unwrap();
            assert_eq!(read, 0, "request bytes were forwarded after revocation");
        });

        let config = RemoteAccessConfig {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
            advertised_endpoint: Some("node.example:18443".into()),
            ..Default::default()
        };
        let server = RemoteAccessServer::bind(
            &config,
            Arc::clone(&node),
            Arc::clone(&pairing),
            internal_addr,
            Arc::new(RemoteTunnelClients::default()),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let pair_link_path = server.pair_link_path().unwrap().to_path_buf();
        let pair_link_uri = std::fs::read_to_string(&pair_link_path).unwrap();
        let link = PairLink::from_uri(&pair_link_uri).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&pair_link_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
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
        let response: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        let public_key = response["box_transport_pubkey"]
            .as_str()
            .expect("signed box key in auth response");
        let signature = response["box_transport_signature"].as_str().unwrap();
        assert_eq!(
            verified_box_pin(&link.node_id, public_key, signature).unwrap(),
            pairing.box_transport_pubkey()
        );
        assert!(verified_box_pin(
            &link.node_id,
            public_key,
            &URL_SAFE_NO_PAD.encode([0u8; 64])
        )
        .is_err());
        let client_id = match serde_json::from_slice::<AuthResponse>(&plaintext).unwrap() {
            AuthResponse::Ok { client_id, .. } => client_id,
            response => panic!("unexpected auth response: {response:?}"),
        };
        assert!(
            !pair_link_path.exists(),
            "successful pairing must consume the protected link"
        );

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

        pairing.revoke(&client_id).unwrap();
        let ciphertext = wire::encode_transport(
            &mut noise,
            b"GET /must-not-forward HTTP/1.1\r\nhost: node\r\n\r\n",
        )
        .unwrap();
        wire::write_frame(&mut writer, &ciphertext).await.unwrap();
        let closed = tokio::time::timeout(
            Duration::from_secs(2),
            wire::read_frame(&mut reader, wire::MAX_TRANSPORT_FRAME),
        )
        .await
        .expect("revoked tunnel should close promptly");
        assert!(closed.is_err(), "revoked tunnel returned another response");

        internal_task.await.unwrap();
        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap();
    }
}
