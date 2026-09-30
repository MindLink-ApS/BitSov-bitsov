//! K1 introductions (slice 1): the node's signed door card, and dialing a
//! node from one.
//!
//! **An introduction is never admission.** Issuing one stores nothing and
//! grants nothing. Opening one dials the introduced node *unprivileged*: no
//! whitelist entry, no persisted peer, no session, no payment. The reader then
//! asks that node for a fresh stateless quote, and every act is paid exactly
//! as for any other stranger. On a closed-mesh node (`admission_mode =
//! "whitelist"`) the dial is refused rather than widening the mesh.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use konsensus_core::introduction::{
    dial_allowed, first_contact_prices, split_endpoint, Introduction, IntroductionFields, Reach,
};
use konsensus_core::traits::transport::TransportError;

use crate::auth::scoped::{Read, ScopedAuth};
use crate::error::ApiError;
use crate::state::AppState;

/// Advertised on `/api/v1/status` when this build serves introduction routes.
pub const CAPABILITY: &str = "introduction_v1";

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Why no dialable peer endpoint is known (stable snake_case codes the app
/// can match on; errors read `introduction_unavailable: <code>`).
pub mod reason {
    /// Wildcard listen, no `advertised_addr`, no `stun_server`.
    pub const NO_DIALABLE_ENDPOINT: &str = "no_dialable_endpoint";
    /// `stun_server` is set but no answer has arrived yet (boot, first try).
    pub const STUN_PENDING: &str = "stun_pending";
    /// The STUN server did not answer (timeout, DNS, socket error).
    pub const STUN_UNREACHABLE: &str = "stun_unreachable";
    /// The STUN server answered with something that is not a usable Binding Success.
    pub const STUN_INVALID_RESPONSE: &str = "stun_invalid_response";
}

/// Where a peer endpoint came from.
pub mod source {
    /// `[network] advertised_addr`, set by the owner.
    pub const ADVERTISED: &str = "advertised";
    /// A concrete (non-wildcard) `listen_addr`.
    pub const LISTEN: &str = "listen";
    /// Public IP learned from the owner's `[network] stun_server`, plus the
    /// TCP peer port of `listen_addr`.
    pub const STUN: &str = "stun";
}

/// The dialable peer endpoint as currently known, or why there is none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerEndpointView {
    /// Dialable `host:port`, never the API address.
    pub endpoint: Option<String>,
    /// `"advertised"`, `"listen"` or `"stun"`; set with `endpoint`.
    pub source: Option<&'static str>,
    /// Why `endpoint` is `None` (see [`reason`]).
    pub reason: Option<&'static str>,
}

impl PeerEndpointView {
    /// A known endpoint.
    pub fn found(endpoint: String, source: &'static str) -> Self {
        Self { endpoint: Some(endpoint), source: Some(source), reason: None }
    }

    /// No endpoint, for `reason`.
    pub fn missing(reason: &'static str) -> Self {
        Self { endpoint: None, source: None, reason: Some(reason) }
    }
}

/// What this node may sign into an introduction. Everything comes from the
/// node's own configuration or its own STUN discovery; the caller supplies
/// nothing.
#[derive(Debug, Clone, Default)]
pub struct IntroductionSettings {
    /// Bitcoin network the node's prices are payable on. `None` (a backend
    /// that does not state its network) means no introduction is offered.
    pub network: Option<String>,
    /// Endpoint fixed at boot from `advertised_addr` or a concrete
    /// `listen_addr`. Always wins; discovery can never replace it.
    pub configured_endpoint: Option<String>,
    /// [`source`] of `configured_endpoint`.
    pub configured_source: Option<&'static str>,
    /// Live STUN discovery result, used only when nothing is configured.
    pub discovered: Arc<RwLock<PeerEndpointView>>,
}

impl IntroductionSettings {
    /// Settings with a fixed, explicit endpoint and no discovery.
    pub fn fixed(network: Option<&str>, endpoint: Option<&str>) -> Self {
        Self {
            network: network.map(Into::into),
            configured_endpoint: endpoint.map(Into::into),
            configured_source: endpoint.map(|_| source::ADVERTISED),
            discovered: Arc::default(),
        }
    }

    /// Dialable `host:port`: the configured endpoint, else the discovered one.
    pub fn endpoint(&self) -> Option<String> {
        self.endpoint_view().endpoint
    }

    /// The endpoint with its source, or the reason there is none.
    pub fn endpoint_view(&self) -> PeerEndpointView {
        if let Some(endpoint) = &self.configured_endpoint {
            return PeerEndpointView {
                endpoint: Some(endpoint.clone()),
                source: self.configured_source.or(Some(source::ADVERTISED)),
                reason: None,
            };
        }
        let mut view = self.discovered.read().unwrap_or_else(|e| e.into_inner()).clone();
        if view.endpoint.is_none() && view.reason.is_none() {
            view.reason = Some(reason::NO_DIALABLE_ENDPOINT);
        }
        view
    }

    /// Record a discovery result. Has no effect on `configured_endpoint`.
    pub fn set_discovered(&self, view: PeerEndpointView) {
        *self.discovered.write().unwrap_or_else(|e| e.into_inner()) = view;
    }

    /// The endpoint, or the `unavailable_prefix: <reason>` error.
    pub(crate) fn require_endpoint(&self, unavailable_prefix: &str) -> Result<String, ApiError> {
        let view = self.endpoint_view();
        view.endpoint.ok_or_else(|| {
            ApiError::Conflict(format!(
                "{unavailable_prefix}: {}",
                view.reason.unwrap_or(reason::NO_DIALABLE_ENDPOINT)
            ))
        })
    }
}

/// `GET /api/v1/introduction`.
#[derive(Debug, Serialize)]
pub struct IntroductionResponse {
    /// The signed card.
    pub card: Introduction,
    /// `bitsov://introduce#…`, for the QR and for sharing.
    pub link: String,
}

/// `POST /api/v1/introduction/open` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIntroductionRequest {
    /// The scanned link, its fragment, or the pasted JSON card.
    pub card: String,
    /// The reader explicitly approved the displayed local-network endpoint.
    /// A sender's signed `reach=local` never grants this permission.
    #[serde(default)]
    pub allow_local: bool,
}

/// `POST /api/v1/introduction/verify`: validate for display without DNS or dialing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyIntroductionRequest {
    /// The scanned link, its fragment, or the pasted JSON card.
    pub card: String,
}

/// `POST /api/v1/introduction/open` result.
#[derive(Debug, Serialize)]
pub struct OpenIntroductionResponse {
    /// The introduced node, now connected.
    pub node_id: String,
    /// The pinned address actually dialed.
    pub dialed: String,
    /// Always `true` on success. Connection is not admission: nothing is
    /// paid, and the connection carries no whitelist privilege from this.
    pub connected: bool,
}

fn now_unix() -> Result<u64, ApiError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))
}

/// `GET /api/v1/introduction` — this node's door card: its key, its peer
/// endpoint and its current first-contact and message prices, signed by the
/// node key, valid for ten minutes. Read scope: every field is the node's own
/// and public by design. Pays, stores and grants nothing.
async fn get_introduction(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let card = issue_card(&state).await?;
    let link = card.to_link();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(IntroductionResponse { card, link }),
    ))
}

/// Sign a fresh card for this node (also used by the sponsor kit's offer).
pub(crate) async fn issue_card(state: &AppState) -> Result<Introduction, ApiError> {
    let settings = &state.introduction;
    let network = settings.network.clone().ok_or_else(|| {
        ApiError::Conflict(
            "introduction_unavailable: this node's Lightning backend does not state a Bitcoin network".into(),
        )
    })?;
    let endpoint = settings.require_endpoint("introduction_unavailable")?;
    let chat = state
        .pricing
        .get_price_msat(konsensus_core::kind::KIND_CHAT)
        .await
        .map_err(|e| ApiError::Internal(format!("price unavailable: {e}")))?;
    let (admission_msat, message_msat) = first_contact_prices(chat);
    let height = state.chain.get_block_height().await.unwrap_or(0);
    let mut intro_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut intro_id);
    let card = Introduction::issue(
        &state.identity,
        IntroductionFields {
            network,
            endpoint,
            admission_msat,
            message_msat,
            price_epoch: height / 2016,
            issued_at: now_unix()?,
            intro_id,
        },
    )
    .map_err(|e| ApiError::Conflict(format!("introduction_unavailable: {e}")))?;
    Ok(card)
}

pub(crate) fn verified_card(state: &AppState, text: &str) -> Result<Introduction, ApiError> {
    let invalid = |e| ApiError::BadRequest(format!("introduction_invalid: {e}"));
    // A sponsor offer may ride after the card (`<card>.<offer>`, K1 slice 2);
    // the card is read and verified on its own. Opening never uses the offer.
    let (card_text, _offer) = konsensus_core::sponsor::split_introduction_link(text);
    let card = Introduction::parse(&card_text).map_err(invalid)?;
    let network = state.introduction.network.as_deref().ok_or_else(|| {
        ApiError::Conflict(
            "introduction_unavailable: this node's Lightning backend does not state a Bitcoin network".into(),
        )
    })?;
    card.verify(now_unix()?, network).map_err(invalid)?;
    Ok(card)
}

/// Stateless read-only verification: no resolution, connection, payment or storage.
async fn verify_introduction(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyIntroductionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let card = verified_card(&state, &req.card)?;
    let link = card.to_link();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(IntroductionResponse { card, link }),
    ))
}

/// Resolve `endpoint` once, refuse it unless every address is allowed for
/// the card's reach, and return one pinned socket address. DNS rebinding
/// between this check and the dial cannot move the connection: the dial uses
/// the pinned IP, and the Noise handshake must then prove the card's key.
async fn pin_endpoint(card: &Introduction) -> Result<SocketAddr, ApiError> {
    let (host, port) = split_endpoint(&card.endpoint)
        .map_err(|e| ApiError::BadRequest(format!("introduction_invalid: {e}")))?;
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(
        DNS_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.collect(),
        Ok(Err(e)) => return Err(ApiError::Transport(format!("cannot resolve {host}: {e}"))),
        Err(_) => return Err(ApiError::Transport(format!("resolving {host} timed out"))),
    };
    if addrs.is_empty() {
        return Err(ApiError::Transport(format!("{host} has no address")));
    }
    if let Some(bad) = addrs.iter().find(|a| !dial_allowed(card.reach, a.ip())) {
        return Err(ApiError::BadRequest(format!(
            "introduction_invalid: {} resolves to {}, not dialable for a {} introduction",
            card.endpoint,
            bad.ip(),
            card.reach
        )));
    }
    Ok(addrs[0])
}

/// `POST /api/v1/introduction/open` — verify a scanned introduction and dial
/// the node it names, so a stateless first-contact quote can be asked of it.
///
/// Checks: size, format, version, this node's network, expiry, the node-key
/// signature, not ourselves, and the endpoint's pinned resolution against the
/// card's reach (never link-local/metadata; private only for a local card
/// with the reader's explicit `allow_local` consent).
/// Then an unprivileged dial whose Noise handshake must authenticate the
/// card's key. Nothing is stored, whitelisted or paid. Read scope, like the
/// card itself: a paired app holds read before its owner grants any budget,
/// and a dial moves no value. Paying still needs the budget grant and the
/// owner's one-time first-contact OK.
async fn open_introduction(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenIntroductionRequest>,
) -> Result<Json<OpenIntroductionResponse>, ApiError> {
    let invalid = |e: konsensus_core::introduction::IntroductionError| {
        ApiError::BadRequest(format!("introduction_invalid: {e}"))
    };
    let card = verified_card(&state, &req.card)?;
    let node = card.node().map_err(invalid)?;
    if node == *state.identity.node_id() {
        return Err(ApiError::BadRequest("introduction_invalid: this is your own introduction".into()));
    }
    if card.reach == Reach::Local && !req.allow_local {
        return Err(ApiError::BadRequest(
            "introduction_local_consent_required: approve the displayed local peer endpoint before opening".into(),
        ));
    }
    let pinned = pin_endpoint(&card).await?;
    match tokio::time::timeout(DIAL_TIMEOUT, state.transport.connect(&node, &pinned.to_string())).await {
        Ok(Ok(())) => Ok(Json(OpenIntroductionResponse {
            node_id: node.to_hex(),
            dialed: pinned.to_string(),
            connected: true,
        })),
        Ok(Err(TransportError::Rejected(_))) => Err(ApiError::Conflict(
            "introduction_closed_mesh: this node dials only peers its owner added; an introduction does not add one".into(),
        )),
        Ok(Err(e)) => Err(ApiError::Transport(format!("could not reach the introduced node: {e}"))),
        Err(_) => Err(ApiError::Transport("could not reach the introduced node: timed out".into())),
    }
}

/// Registers the introduction routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/introduction", get(get_introduction))
        .route("/api/v1/introduction/verify", post(verify_introduction))
        .route("/api/v1/introduction/open", post(open_introduction))
}
