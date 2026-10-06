//! Owner API for FrontDoorCard v1: create/update/export as link + QR payload,
//! verify a pasted card for display, and open (unprivileged dial) so Knock
//! can use the existing first-contact flow. Opening is never admission.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use konsensus_core::card_cache::CardCache;
use konsensus_core::front_door::{
    Avatar, FrontDoorCard, FrontDoorCv, FrontDoorError, FrontDoorFields, FrontDoorLink,
    FrontDoorMedia, FrontDoorPrices, FrontDoorProfile, FrontDoorSite, ProfileKind,
};
use konsensus_core::introduction::{dial_allowed, first_contact_prices, split_endpoint, Reach};
use konsensus_core::traits::transport::TransportError;

use crate::auth::scoped::{FrontDoorWrite, Read, ScopedAuth};
use crate::error::ApiError;
use crate::state::AppState;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const CARD_FILE: &str = "front-door.json";
const SEQ_FILE: &str = "front-door.seq";
/// Max gap between own published card seq and an adopted floor from
/// `front-door.seq` or a salvaged corrupt-card seq. A hand-edited
/// `u64::MAX` floor would otherwise lock publish forever via
/// `saturating_add(1)` → `SeqNotMonotonic`.
const SEQ_FLOOR_ADOPT_BOUND: u64 = 1_000_000;

/// Advertised on `/api/v1/status`.
pub const CAPABILITY: &str = "front_door_v1";

/// Published card, loaded from and written to `pages/front-door.json`.
///
/// A separate `front-door.seq` floor survives a corrupt or tampered card file
/// so the next publish never silently restarts at seq 1.
#[derive(Debug, Clone, Default)]
pub struct FrontDoorStore {
    pub card: Arc<Mutex<Option<FrontDoorCard>>>,
    /// Highest seq we have ever issued or salvaged; next publish is floor+1.
    pub seq_floor: Arc<Mutex<u64>>,
    /// Other nodes' verified cards, from porch reads (BROWSE.md §5). In memory.
    pub known: Arc<Mutex<CardCache>>,
    /// Absolute path of the card file, when a content or data dir exists.
    persist: Option<PathBuf>,
}

impl FrontDoorStore {
    /// Re-derive a published card from the gate tariff, including cards saved by
    /// older versions. Persist and re-sign only when the price changes; reads
    /// neither renew the expiry nor change the owner's profile.
    pub async fn priced_card(
        &self,
        identity: &konsensus_core::identity::NodeIdentity,
        pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
        gate: &konsensus_core::gate::PaymentGate,
    ) -> Result<Option<FrontDoorCard>, ApiError> {
        let price = porch_page_price(pricing, gate).await?;
        let mut store = self.card.lock().await;
        let Some(card) = store.as_ref() else {
            return Ok(None);
        };
        if card.prices.page_msat == price {
            return Ok(Some(card.clone()));
        }
        let mut floor = self.seq_floor.lock().await;
        let seq = card
            .seq
            .max(*floor)
            .checked_add(1)
            .ok_or_else(|| ApiError::Conflict("front-door sequence exhausted".into()))?;
        let mut prices = card.prices.clone();
        prices.page_msat = price;
        let updated = FrontDoorCard::issue(
            identity,
            FrontDoorFields {
                network: card.network.clone(),
                endpoint: card.endpoint.clone(),
                seq,
                issued_at: card.issued_at,
                prices,
                profile: card.profile.clone(),
                cv: card.cv.clone(),
                media: card.media.clone(),
                site: card.site.clone(),
                links: card.links.clone(),
            },
        )
        .map_err(map_err)?;
        self.save(&updated)?;
        *floor = seq;
        *store = Some(updated.clone());
        Ok(Some(updated))
    }

    /// Resolve `content_dir/front-door.json`, else `data_dir/pages/front-door.json`.
    pub fn persist_path(content_dir: Option<&Path>, data_dir: Option<&Path>) -> Option<PathBuf> {
        if let Some(dir) = content_dir {
            return Some(dir.join(CARD_FILE));
        }
        data_dir.map(|d| d.join("pages").join(CARD_FILE))
    }

    fn seq_path(card_path: &Path) -> PathBuf {
        card_path.with_file_name(SEQ_FILE)
    }

    /// Load any previously published card from disk.
    ///
    /// `own_node_id` is this node's hex Ed25519 id. Foreign cards are ignored
    /// (R2). Corrupt/tampered cards do not load, but their seq (and any
    /// `front-door.seq` floor) still raises the monotonic floor (R1), capped
    /// so a hand-edited absurd floor cannot lock publishing.
    pub fn load(content_dir: Option<&Path>, data_dir: Option<&Path>, own_node_id: &str) -> Self {
        let persist = Self::persist_path(content_dir, data_dir);
        let raw_file_floor = persist
            .as_ref()
            .map(|p| read_seq_floor(&Self::seq_path(p)))
            .unwrap_or(0);
        let mut own_card_seq = 0u64;
        let mut salvaged_for_floor: Option<u64> = None;
        let card = persist
            .as_ref()
            .and_then(|p| match load_card(p, own_node_id) {
                LoadOutcome::Ours(c) => {
                    own_card_seq = c.seq;
                    Some(*c)
                }
                LoadOutcome::Foreign { seq } => {
                    tracing::warn!(
                        path = %p.display(),
                        seq,
                        "ignoring foreign front-door card (not our node_id)"
                    );
                    // Do not adopt a stranger's seq as ours — only our seq file counts.
                    None
                }
                LoadOutcome::Missing => None,
                LoadOutcome::Corrupt {
                    salvaged_seq,
                    error,
                } => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %error,
                        salvaged_seq,
                        "front-door card load failed; keeping seq floor"
                    );
                    salvaged_for_floor = salvaged_seq;
                    None
                }
            });
        let mut floor = own_card_seq;
        floor = floor.max(cap_adopted_seq_floor(
            raw_file_floor,
            own_card_seq,
            "front-door.seq",
        ));
        if let Some(s) = salvaged_for_floor {
            floor = floor.max(cap_adopted_seq_floor(s, own_card_seq, "salvaged_card_seq"));
        }
        if floor > 0 {
            if let Some(path) = persist.as_ref() {
                let _ = write_seq_floor(&Self::seq_path(path), floor);
            }
        }
        Self {
            card: Arc::new(Mutex::new(card)),
            seq_floor: Arc::new(Mutex::new(floor)),
            known: Default::default(),
            persist,
        }
    }

    fn save(&self, card: &FrontDoorCard) -> Result<(), ApiError> {
        let Some(path) = self.persist.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ApiError::Internal(format!(
                    "front_door persist mkdir {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let bytes = serde_json::to_vec_pretty(card)
            .map_err(|e| ApiError::Internal(format!("front_door persist encode: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| {
            ApiError::Internal(format!("front_door persist write {}: {e}", tmp.display()))
        })?;
        std::fs::rename(&tmp, path).map_err(|e| {
            ApiError::Internal(format!("front_door persist rename {}: {e}", path.display()))
        })?;
        write_seq_floor(&Self::seq_path(path), card.seq)?;
        Ok(())
    }
}

enum LoadOutcome {
    Ours(Box<FrontDoorCard>),
    Foreign {
        seq: u64,
    },
    Missing,
    Corrupt {
        salvaged_seq: Option<u64>,
        error: String,
    },
}

fn load_card(path: &Path, own_node_id: &str) -> LoadOutcome {
    if !path.exists() {
        return LoadOutcome::Missing;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return LoadOutcome::Corrupt {
                salvaged_seq: None,
                error: e.to_string(),
            }
        }
    };
    let salvaged_seq = salvage_seq(&bytes);
    let card: FrontDoorCard = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(e) => {
            return LoadOutcome::Corrupt {
                salvaged_seq,
                error: e.to_string(),
            }
        }
    };
    if let Err(e) = card.verify_signature() {
        return LoadOutcome::Corrupt {
            salvaged_seq: salvaged_seq.or(Some(card.seq)),
            error: e.to_string(),
        };
    }
    if !own_node_id.is_empty() && card.node_id != own_node_id {
        return LoadOutcome::Foreign { seq: card.seq };
    }
    LoadOutcome::Ours(Box::new(card))
}

fn salvage_seq(bytes: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("seq")?.as_u64()
}

fn read_seq_floor(path: &Path) -> u64 {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0;
    }
    match trimmed.parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            tracing::warn!(
                path = %path.display(),
                value = %trimmed,
                "front-door seq file is not a valid u64; ignoring (floor stays 0 until a card seq is known)"
            );
            0
        }
    }
}

/// Refuse a candidate floor above `own_card_seq + SEQ_FLOOR_ADOPT_BOUND`.
/// Returns `own_card_seq` (safe published floor) when the candidate is absurd.
fn cap_adopted_seq_floor(candidate: u64, own_card_seq: u64, source: &str) -> u64 {
    let max_ok = own_card_seq.saturating_add(SEQ_FLOOR_ADOPT_BOUND);
    if candidate > max_ok {
        tracing::warn!(
            candidate,
            own_card_seq,
            max_ok,
            bound = SEQ_FLOOR_ADOPT_BOUND,
            source,
            "refusing front-door seq floor above own card seq + adopt bound"
        );
        return own_card_seq;
    }
    candidate
}

fn write_seq_floor(path: &Path, seq: u64) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ApiError::Internal(format!("front_door seq mkdir {}: {e}", parent.display()))
        })?;
    }
    let tmp = path.with_extension("seq.tmp");
    std::fs::write(&tmp, format!("{seq}\n"))
        .map_err(|e| ApiError::Internal(format!("front_door seq write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        ApiError::Internal(format!("front_door seq rename {}: {e}", path.display()))
    })?;
    Ok(())
}

/// `GET` / `PUT` / verify response.
#[derive(Debug, Serialize)]
pub struct FrontDoorResponse {
    pub card: FrontDoorCard,
    /// `bitsov://front-door#…` — also the QR payload.
    pub link: String,
    /// Same as `link`; named for clients that expect a dedicated QR field.
    pub qr_payload: String,
    /// Signature (and shape) checked. Always true on success from this route.
    pub verified: bool,
    /// Within lifetime and on this node's network.
    pub fresh: bool,
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
    /// Accepted for compatibility; published page prices are derived from web_content.
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

fn map_err(e: FrontDoorError) -> ApiError {
    ApiError::BadRequest(format!("front_door_invalid: {e}"))
}

fn response_for(
    card: FrontDoorCard,
    network: Option<&str>,
    now: u64,
) -> Result<FrontDoorResponse, ApiError> {
    let link = card.to_link().map_err(map_err)?;
    let fresh = match network {
        Some(net) => card.verify(now, net).is_ok(),
        None => card.expires_at > now,
    };
    Ok(FrontDoorResponse {
        qr_payload: link.clone(),
        link,
        card,
        verified: true,
        fresh,
    })
}

/// `GET /api/v1/front-door` — the owner's published card, or 404.
async fn get_front_door(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let card = state
        .front_door
        .priced_card(&state.identity, state.pricing.as_ref(), &state.gate)
        .await?
        .ok_or_else(|| ApiError::NotFound("front_door_missing: publish one first".into()))?;
    let body = response_for(card, state.introduction.network.as_deref(), now_unix()?)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

/// `PUT /api/v1/front-door` — create or update; bumps `seq`, re-signs, 7-day expiry.
///
/// Demands `front_door` or `admin` ([`FrontDoorWrite`]). A paired app holds
/// `front_door` only while an owner grant is live; `admin` is never granted to
/// it. Publishing moves no value.
async fn put_front_door(
    auth: ScopedAuth<FrontDoorWrite>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertFrontDoorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let network = state.introduction.network.clone().ok_or_else(|| {
        ApiError::Conflict(
            "front_door_unavailable: this node's Lightning backend does not state a Bitcoin network".into(),
        )
    })?;
    let endpoint = state.introduction.require_endpoint("front_door_unavailable")?;
    let chat = state
        .pricing
        .get_price_msat(konsensus_core::kind::KIND_CHAT)
        .await
        .map_err(|e| ApiError::Internal(format!("price unavailable: {e}")))?;
    let (default_admission, default_message) = first_contact_prices(chat);
    let page_msat = porch_page_price(state.pricing.as_ref(), &state.gate).await?;
    let height = state.chain.get_block_height().await.unwrap_or(0);

    let mut store = state.front_door.card.lock().await;
    let mut floor = state.front_door.seq_floor.lock().await;
    let prior_seq = store.as_ref().map(|c| c.seq).unwrap_or(0).max(*floor);
    let next_seq = prior_seq.saturating_add(1);
    if next_seq <= prior_seq {
        return Err(ApiError::Conflict(format!(
            "front_door_unavailable: {}",
            FrontDoorError::SeqNotMonotonic
        )));
    }
    let card = FrontDoorCard::issue(
        &state.identity,
        FrontDoorFields {
            network: network.clone(),
            endpoint,
            seq: next_seq,
            issued_at: now_unix()?,
            prices: FrontDoorPrices {
                admission_msat: req.admission_msat.unwrap_or(default_admission),
                message_msat: req.message_msat.unwrap_or(default_message),
                page_msat,
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
    state.front_door.save(&card)?;
    // Logged like the grant that allowed it: who published which sequence.
    tracing::info!(
        seq = card.seq,
        paired_client = auth.pairing.as_ref().map(|p| p.client_id.as_str()).unwrap_or("-"),
        via = if auth.has(crate::auth::Scope::Admin) { "admin" } else { "front_door grant" },
        "front door published"
    );
    *floor = card.seq;
    *store = Some(card.clone());
    drop(floor);
    drop(store);
    let body = response_for(card, Some(network.as_str()), now_unix()?)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

/// `POST /api/v1/front-door/verify` — validate a pasted/scanned card for display.
///
/// Signature is always required. Expired or wrong-network cards may still be
/// returned for "as of <date>" UI with `verified: true, fresh: false`.
async fn verify_front_door(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyFrontDoorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let card = FrontDoorCard::parse(&req.card).map_err(map_err)?;
    // F1: signature before expiry/network — unsigned cards never look verified.
    card.verify_signature().map_err(map_err)?;
    // R3: never invent a network; fail closed when the node has none.
    let network = state.introduction.network.as_deref().ok_or_else(|| {
        ApiError::Conflict(
            "front_door_unavailable: this node's Lightning backend does not state a Bitcoin network"
                .into(),
        )
    })?;
    let now = now_unix()?;
    let fresh = match card.verify(now, network) {
        Ok(()) => true,
        Err(FrontDoorError::Expired(_)) | Err(FrontDoorError::WrongNetwork { .. }) => false,
        Err(other) => return Err(map_err(other)),
    };
    let link = card.to_link().map_err(map_err)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(FrontDoorResponse {
            qr_payload: link.clone(),
            link,
            card,
            verified: true,
            fresh,
        }),
    ))
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
    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
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
        .route(
            "/api/v1/front-door",
            get(get_front_door).put(put_front_door),
        )
        .route("/api/v1/front-door/verify", post(verify_front_door))
        .route("/api/v1/front-door/open", post(open_front_door))
}

/// Public cards and previews have no peer trust discount.
pub async fn porch_page_price(
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    gate: &konsensus_core::gate::PaymentGate,
) -> Result<u64, ApiError> {
    let kind = konsensus_core::kind::KIND_PAGE_REQUEST;
    let base = pricing
        .get_price_msat(kind)
        .await
        .map_err(|e| ApiError::Internal(format!("price unavailable: {e}")))?;
    Ok(gate.price_with_floor_msat(base))
}
