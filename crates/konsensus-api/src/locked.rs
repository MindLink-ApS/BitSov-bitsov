//! Identity-free, existing-device-only remote unlock. No live router is mounted.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde_json::json;
use tokio::{sync::oneshot, time::Instant};
use zeroize::Zeroizing;

use crate::{
    pairing::{
        device::{owner_approval_message, verify_owner_approval},
        PairedClient, PairingService,
    },
    rate_limit::RemoteTunnelClients,
};

#[path = "locked_body.rs"]
pub(crate) mod body;

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Exact device-signed bytes; all authority fields come from server state.
pub fn unlock_message(
    node: &str,
    client_id: &str,
    epoch: u64,
    key_id: &str,
    challenge: &str,
    box_transport_pubkey: &str,
) -> String {
    format!("bitsov-node-unlock-v1\nnode:{node}\nclient:{client_id}\nepoch:{epoch}\nkey:{key_id}\nchallenge:{challenge}\nbox_transport:{box_transport_pubkey}")
}

/// Deliberately terse: errors must never include a password or decrypted seed.
#[derive(Clone, Copy, Debug)]
pub enum UnlockError {
    /// Invalid challenge, device signature, password or identity.
    Failed,
    /// Unknown or owner-unapproved device record.
    DeviceUnknown,
    /// A transition already owns the password handoff.
    AlreadyUnlocking,
    /// Device or process failure budget exhausted.
    RateLimited,
}
impl IntoResponse for UnlockError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Failed => (StatusCode::UNAUTHORIZED, "unlock_failed"),
            Self::DeviceUnknown => (StatusCode::FORBIDDEN, "device_unknown"),
            Self::AlreadyUnlocking => (StatusCode::CONFLICT, "already_unlocking"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "unlock_rate_limited"),
        };
        (status, Json(json!({"error": code}))).into_response()
    }
}

type PasswordVerifier =
    dyn Fn(&str) -> Result<(String, ed25519_dalek::VerifyingKey), UnlockError> + Send + Sync;
struct Challenge {
    value: String,
    client: PairedClient,
    deadline: Instant,
}
#[derive(Default)]
struct Attempts {
    total: u32,
    keys: HashMap<String, Vec<Instant>>,
}
impl Attempts {
    fn limited(&mut self, key: &str) -> bool {
        let now = Instant::now();
        self.keys.retain(|_, failures| {
            failures.retain(|t| now.duration_since(*t) < FAILURE_WINDOW);
            !failures.is_empty()
        });
        self.total >= 20 || self.keys.get(key).is_some_and(|v| v.len() >= 5)
    }
    fn failed(&mut self, key: &str, error: UnlockError) -> UnlockError {
        self.total += 1;
        self.keys
            .entry(key.to_owned())
            .or_default()
            .push(Instant::now());
        if self.limited(key) {
            UnlockError::RateLimited
        } else {
            error
        }
    }
}

/// Locked startup state. Only the node-side verifier ever decrypts the seed.
pub struct LockedState {
    node_id: String,
    locked_since: i64,
    pairing: Arc<PairingService>,
    clients: Arc<RemoteTunnelClients>,
    challenges: Mutex<HashMap<String, Challenge>>,
    attempts: Mutex<Attempts>,
    // The guard lives inside blocking verification as well, so cancelling an
    // HTTP request cannot admit a second Argon2 job or a second transition.
    transition: Arc<tokio::sync::Mutex<Option<oneshot::Sender<Zeroizing<String>>>>>,
    verify_password: Arc<PasswordVerifier>,
    /// Host and Origin allowlist for the public loopback listener. Tunnel
    /// peers skip it: the phone bridge sends `Host: localhost` with no port.
    /// Absent means every non-tunnel request fails closed.
    local_admission: Option<crate::local_request::LocalRequestPolicy>,
}
impl LockedState {
    /// The verifier returns the seed-derived node id and owner verifying key.
    /// It must not retain the supplied password or expose crypto error details.
    pub fn new(
        node_id: String,
        pairing: Arc<PairingService>,
        clients: Arc<RemoteTunnelClients>,
        verify_password: impl Fn(&str) -> Result<(String, ed25519_dalek::VerifyingKey), UnlockError>
            + Send
            + Sync
            + 'static,
        handoff: oneshot::Sender<Zeroizing<String>>,
    ) -> Self {
        Self {
            node_id,
            locked_since: chrono::Utc::now().timestamp(),
            pairing,
            clients,
            challenges: Mutex::new(HashMap::new()),
            attempts: Mutex::new(Attempts::default()),
            transition: Arc::new(tokio::sync::Mutex::new(Some(handoff))),
            verify_password: Arc::new(verify_password),
            local_admission: None,
        }
    }

    /// Trust `Host` / `Origin` only when they name this listener. Pass the
    /// address returned by `local_addr()` after bind, never a pre-bind port 0.
    pub fn with_local_admission(mut self, addr: SocketAddr) -> Self {
        self.local_admission = Some(crate::local_request::LocalRequestPolicy::new(
            addr,
            Vec::new(),
        ));
        self
    }

    /// The locked status shared by HTTP and the owner-only control socket.
    pub fn status(&self) -> serde_json::Value {
        json!({"state": "locked", "node_id": self.node_id, "fingerprint": self.pairing.bound_fingerprint(), "locked_since": self.locked_since, "attempts_left": 20u32.saturating_sub(self.attempts.lock().unwrap_or_else(|e| e.into_inner()).total), "hosted_by": self.pairing.hosted_by()})
    }

    fn client(&self, peer: Option<ConnectInfo<SocketAddr>>) -> Result<PairedClient, UnlockError> {
        let id = self
            .clients
            .client_id(peer.ok_or(UnlockError::Failed)?.0)
            .ok_or(UnlockError::Failed)?;
        self.pairing
            .list_clients()
            .into_iter()
            .find(|c| {
                c.client_id == id.as_ref()
                    && c.identity_fingerprint == self.pairing.bound_fingerprint()
            })
            .ok_or(UnlockError::Failed)
    }
}

/// Exactly four paths. No auth/local, pairing, health, peers or wallet handlers.
///
/// A registered Noise-bridge peer skips the Host check. Every other caller,
/// including `/livez` and `/api/v1/node/lock`, must present a Host (and Origin,
/// when sent) for the public loopback address.
pub fn locked_router(state: Arc<LockedState>) -> Router {
    Router::new()
        .route("/livez", get(|| async { StatusCode::OK }))
        .route("/api/v1/node/lock", get(lock_status))
        .route("/api/v1/node/unlock/challenge", post(challenge))
        .route("/api/v1/node/unlock", post(unlock))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            admit_local_or_tunnel,
        ))
        .with_state(state)
}

async fn admit_local_or_tunnel(
    State(state): State<Arc<LockedState>>,
    request: Request,
    next: Next,
) -> Result<Response, crate::local_request::LocalRequestRejection> {
    // Read the extension; do not extract `ConnectInfo`, or the unlock
    // handlers lose the peer the tunnel registered.
    let tunneled = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| state.clients.client_id(*peer).is_some());
    if !tunneled {
        match state.local_admission.as_ref() {
            Some(policy) => policy.validate(request.headers())?,
            None => return Err(crate::local_request::admission_required()),
        }
    }
    Ok(next.run(request).await)
}
async fn lock_status(State(state): State<Arc<LockedState>>) -> Json<serde_json::Value> {
    Json(state.status())
}
async fn challenge(
    State(state): State<Arc<LockedState>>,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<serde_json::Value>, UnlockError> {
    let client = state.client(peer)?;
    let guard = state
        .transition
        .try_lock()
        .map_err(|_| UnlockError::AlreadyUnlocking)?;
    if guard.is_none() {
        return Err(UnlockError::AlreadyUnlocking);
    }
    if state
        .attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .total
        >= 20
    {
        return Err(UnlockError::RateLimited);
    }
    let key_ids: Vec<_> = state
        .pairing
        .device_keys_for(&client.client_id)
        .into_iter()
        .map(|k| k.key_id)
        .collect();
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    let value = hex::encode(random);
    let mut challenges = state.challenges.lock().unwrap_or_else(|e| e.into_inner());
    challenges.retain(|_, c| c.deadline > Instant::now());
    // One outstanding challenge per durable pairing bounds memory and retires
    // an older challenge when a device retries.
    challenges.insert(
        client.client_id.clone(),
        Challenge {
            value: value.clone(),
            client,
            deadline: Instant::now() + CHALLENGE_TTL,
        },
    );
    Ok(Json(
        json!({"challenge": value, "expires_at": chrono::Utc::now().timestamp() + 120, "key_ids": key_ids}),
    ))
}

async fn unlock(
    State(state): State<Arc<LockedState>>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<StatusCode, UnlockError> {
    let client = state.client(peer)?;
    let mut transition = state
        .transition
        .clone()
        .try_lock_owned()
        .map_err(|_| UnlockError::AlreadyUnlocking)?;
    if transition.is_none() {
        return Err(UnlockError::AlreadyUnlocking);
    }
    // Never use Json<UnlockBody>: its aggregate body is not zeroizing.
    let raw = body::read(request).await.ok_or(UnlockError::Failed)?;
    let body = body::parse(&raw)?;
    let issued = {
        let mut challenges = state.challenges.lock().unwrap_or_else(|e| e.into_inner());
        let issuer = challenges
            .iter()
            .find(|(_, c)| c.value == body.challenge)
            .map(|(id, _)| id.clone())
            .ok_or(UnlockError::Failed)?;
        challenges.remove(&issuer).ok_or(UnlockError::Failed)?
    };
    if issued.deadline <= Instant::now() || issued.client != client {
        return Err(UnlockError::Failed);
    }
    let key = state
        .pairing
        .device_keys_for(&client.client_id)
        .into_iter()
        .find(|k| k.key_id == body.key_id && k.client_pubkey == client.client_pubkey)
        .ok_or(UnlockError::DeviceUnknown)?;
    if state
        .attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .limited(&key.key_id)
    {
        return Err(UnlockError::RateLimited);
    }
    let message = unlock_message(
        &state.pairing.bound_fingerprint(),
        &client.client_id,
        client.epoch,
        &key.key_id,
        &body.challenge,
        &hex::encode(state.pairing.box_transport_pubkey()),
    );
    let public = hex::decode(&key.public_key).map_err(|_| UnlockError::DeviceUnknown)?;
    let signature = hex::decode(&body.signature).map_err(|_| UnlockError::Failed)?;
    if ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &public)
        .verify(message.as_bytes(), &signature)
        .is_err()
    {
        return Err(state
            .attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .failed(&key.key_id, UnlockError::Failed));
    }
    tokio::task::spawn_blocking(move || {
        tracing::debug!(
            code = "UNLOCK_VERIFYING",
            "verifying encrypted seed for remote unlock"
        );
        let verified = (state.verify_password)(&body.password).and_then(|(node_id, owner)| {
            let message = owner_approval_message(
                &state.pairing.bound_fingerprint(),
                &client.client_pubkey,
                client.epoch,
                &key.public_key,
            );
            if verify_owner_approval(&owner, &message, &key.owner_approval).is_err() {
                tracing::warn!(
                    code = "UNLOCK_DEVICE_RECORD_INVALID",
                    "unlock device owner approval did not verify"
                );
                return Err(UnlockError::DeviceUnknown);
            }
            if node_id != state.node_id {
                return Err(UnlockError::Failed);
            }
            // Revocation during costly password derivation must still win.
            if !state.pairing.list_clients().contains(&client)
                || !state
                    .pairing
                    .device_keys_for(&client.client_id)
                    .contains(&key)
            {
                return Err(UnlockError::DeviceUnknown);
            }
            Ok(())
        });
        if let Err(error) = verified {
            return Err(state
                .attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .failed(&key.key_id, error));
        }
        transition
            .take()
            .ok_or(UnlockError::AlreadyUnlocking)?
            .send(body.password)
            .map_err(|_| UnlockError::Failed)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| UnlockError::Failed)?
}
