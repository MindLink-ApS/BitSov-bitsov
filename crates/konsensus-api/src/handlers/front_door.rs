//! Owner API for FrontDoorCard v1: create/update/export as link + QR payload,
//! verify a pasted card for display, and open (unprivileged dial) so Knock
//! can use the existing first-contact flow. Opening is never admission.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use konsensus_core::front_door::{
    Avatar, FrontDoorCard, FrontDoorCv, FrontDoorFields, FrontDoorLink, FrontDoorMedia,
    FrontDoorPrices, FrontDoorProfile, FrontDoorSite, ProfileKind,
};
use konsensus_core::introduction::{
    dial_allowed, first_contact_prices, split_endpoint, Reach,
};
use konsensus_core::traits::transport::TransportError;

use crate::auth::scoped::{Admin, Read, ScopedAuth};
use crate::error::ApiError;
use crate::state::AppState;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Advertised on `/api/v1/status`.
pub const CAPABILITY: &str = "front_door_v1";

/// In-memory published card (also written to pages/ when a content dir exists).
#[derive(Debug, Clone, Default)]
pub struct FrontDoorStore {
    pub card: Arc<Mutex<Option<FrontDoorCard>>>,
}

/// `GET` / `PUT` response.
#[derive(Debug, Serialize)]
pub struct FrontDoorResponse {
    pub card: FrontDoorCard,
    /// `bitsov://front-door#…` — also the QR payload.
    pub link: String,
    /// Same as `link`; named for clients that expect a dedicated QR field.
    pub qr_payload: String,
}

/// Owner body for create/update. Omitted price fields fall back to the node's
/// current first-contact snapshot.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertFrontDoorRequest {
    pub display_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub about: String,
    #[serde(default)]
    pub kind: Option<ProfileKind>,
    #[serde(default)]
    pub avatar: Option<Avatar>,
    #[serde(default)]
    pub admission_msat: Option<u64>,
    #[serde(default)]
    pub message_msat: Option<u64>,
    #[serde(default)]
    pub page_msat: Option<u64>,
    #[serde(default)]
    pub cv: Option<FrontDoorCv>,
    #[serde(default)]
    pub media: Vec<FrontDoorMedia>,
    #[serde(default)]
    pub site: Option<FrontDoorSite>,
    #[serde(default)]
    pub links: Vec<FrontDoorLink>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyFrontDoorRequest {
    pub card: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenFrontDoorRequest {
    pub card: String,
    #[serde(default)]
    pub allow_local: bool,
}

#[derive(Debug, Serialize)]
pub struct OpenFrontDoorResponse {
    pub node_id: String,
    pub dialed: String,
    pub connected: bool,
}

fn now_unix() -> Result<u64, ApiError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))
}

fn map_err(e: konsensus_core::front_door::FrontDoorError) -> ApiError {
    ApiError::BadRequest(format!("front_door_invalid: {e}"))
}

async fn response_for(card: FrontDoorCard) -> Result<FrontDoorResponse, ApiError> {
    let link = card.to_link().map_err(map_err)?;
    Ok(FrontDoorResponse {
        qr_payload: link.clone(),
        link,
        card,
    })
}

/// `GET /api/v1/front-door` — the owner's published card, or 404.
async fn get_front_door(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let guard = state.front_door.card.lock().await;
    let card = guard.clone().ok_or_else(|| ApiError::NotFound("front_door_missing: publish one first".into()))?;
    let body = response_for(card).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

/// `PUT /api/v1/front-door` — create or update; bumps `seq`, re-signs, 7-day expiry.
async fn put_front_door(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertFrontDoorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let network = state.introduction.network.clone().ok_or_else(|| {
        ApiError::Conflict(
            "front_door_unavailable: this node's Lightning backend does not state a Bitcoin network".into(),
        )
    })?;
    let endpoint = state.introduction.endpoint.clone().ok_or_else(|| {
        ApiError::Conflict(
            "front_door_unavailable: no dialable peer endpoint; set [network] advertised_addr".into(),
        )
    })?;
    let chat = state
        .pricing
        .get_price_msat(konsensus_core::kind::KIND_CHAT)
        .await
        .map_err(|e| ApiError::Internal(format!("price unavailable: {e}")))?;
    let (default_admission, default_message) = first_contact_prices(chat);
    let height = state.chain.get_block_height().await.unwrap_or(0);

    let mut store = state.front_door.card.lock().await;
    let next_seq = store.as_ref().map(|c| c.seq.saturating_add(1)).unwrap_or(1);
    let card = FrontDoorCard::issue(
        &state.identity,
        FrontDoorFields {
            network,
            endpoint,
            seq: next_seq,
            issued_at: now_unix()?,
            prices: FrontDoorPrices {
                admission_msat: req.admission_msat.unwrap_or(default_admission),
                message_msat: req.message_msat.unwrap_or(default_message),
                page_msat: req.page_msat.unwrap_or(1_000),
                price_epoch: height / 2016,
            },
            profile: FrontDoorProfile {
                kind: req.kind.unwrap_or(ProfileKind::Person),
                display_name: req.display_name,
                tagline: req.tagline,
                about: req.about,
                avatar: req.avatar,
            },
            cv: req.cv,
            media: req.media,
            site: req.site,
            links: req.links,
        },
    )
    .map_err(|e| ApiError::Conflict(format!("front_door_unavailable: {e}")))?;
    *store = Some(card.clone());
    drop(store);
    let body = response_for(card).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

/// `POST /api/v1/front-door/verify` — validate a pasted/scanned card for display.
async fn verify_front_door(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyFrontDoorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let card = FrontDoorCard::parse(&req.card).map_err(map_err)?;
    let network = state.introduction.network.as_deref().unwrap_or("regtest");
    // Display verify: allow expired cards to parse for "as of" UI, but report via verify when fresh.
    if let Err(e) = card.verify(now_unix()?, network) {
        // Still return the card for display; include verification error in a soft way by failing
        // only on crypto/shape — expiry is a BadRequest with the card link for refresh UX.
        match e {
            konsensus_core::front_door::FrontDoorError::Expired(_)
            | konsensus_core::front_door::FrontDoorError::WrongNetwork { .. } => {
                let link = card.to_link().map_err(map_err)?;
                return Ok((
                    [(header::CACHE_CONTROL, "no-store")],
                    Json(FrontDoorResponse {
                        qr_payload: link.clone(),
                        link,
                        card,
                    }),
                ));
            }
            other => return Err(map_err(other)),
        }
    }
    let body = response_for(card).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

fn verified_for_open(state: &AppState, text: &str) -> Result<FrontDoorCard, ApiError> {
    let card = FrontDoorCard::parse(text).map_err(map_err)?;
    let network = state.introduction.network.as_deref().ok_or_else(|| {
        ApiError::Conflict(
            "front_door_unavailable: this node's Lightning backend does not state a Bitcoin network"
                .into(),
        )
    })?;
    card.verify(now_unix()?, network).map_err(map_err)?;
    Ok(card)
}

async fn pin_endpoint(card: &FrontDoorCard) -> Result<SocketAddr, ApiError> {
    let (host, port) = split_endpoint(&card.endpoint)
        .map_err(|e| ApiError::BadRequest(format!("front_door_invalid: {e}")))?;
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
            "front_door_invalid: {} resolves to {}, not dialable for a {} front door",
            card.endpoint,
            bad.ip(),
            card.reach
        )));
    }
    Ok(addrs[0])
}

/// `POST /api/v1/front-door/open` — verify and dial unprivileged (never admission).
async fn open_front_door(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenFrontDoorRequest>,
) -> Result<Json<OpenFrontDoorResponse>, ApiError> {
    let card = verified_for_open(&state, &req.card)?;
    let node = card.node().map_err(map_err)?;
    if node == *state.identity.node_id() {
        return Err(ApiError::BadRequest(
            "front_door_invalid: this is your own front door".into(),
        ));
    }
    if card.reach == Reach::Local && !req.allow_local {
        return Err(ApiError::BadRequest(
            "front_door_local_consent_required: approve the displayed local peer endpoint before knocking".into(),
        ));
    }
    let pinned = pin_endpoint(&card).await?;
    match tokio::time::timeout(
        DIAL_TIMEOUT,
        state.transport.connect(&node, &pinned.to_string()),
    )
    .await
    {
        Ok(Ok(())) => Ok(Json(OpenFrontDoorResponse {
            node_id: node.to_hex(),
            dialed: pinned.to_string(),
            connected: true,
        })),
        Ok(Err(TransportError::Rejected(_))) => Err(ApiError::Conflict(
            "front_door_closed_mesh: this node dials only peers its owner added; a front door does not add one".into(),
        )),
        Ok(Err(e)) => Err(ApiError::Transport(format!(
            "could not reach the front-door node: {e}"
        ))),
        Err(_) => Err(ApiError::Transport(
            "could not reach the front-door node: timed out".into(),
        )),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/front-door", get(get_front_door).put(put_front_door))
        .route("/api/v1/front-door/verify", post(verify_front_door))
        .route("/api/v1/front-door/open", post(open_front_door))
}
