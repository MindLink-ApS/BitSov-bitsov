//! Browse: paid porch reads of another node's public surface
//! (`docs/protocol/BROWSE.md`).
//!
//! `POST /api/v1/browse/fetch` pays for one kind-500 read through compose's
//! own spend path (same authority, caps and budget), waits for the reply the
//! gate bound to that payment, and returns it. A card read is verified against
//! the node that was paid and offered to the card cache.
//! `GET /api/v1/browse/cards` lists the cache.
//!
//! Refused before anything is paid: a path the porch never serves, a node we
//! are not connected to, a node we hold no E2EE session with (Knock first; a
//! read never pays admission), and a second read from a node while one is in
//! flight.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use konsensus_core::card_cache::Offer;
use konsensus_core::front_door::FrontDoorCard;
use konsensus_core::kind::{KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE};
use konsensus_core::payloads::content::{
    is_porch_path, PageRequest, PageResponse, PageStatus, MAX_PORCH_BODY_BYTES, PORCH_CARD_PATH,
};
use konsensus_core::{MessageId, NodeId};

use crate::auth::scoped::{Read, ScopedAuth};
use crate::error::ApiError;
use crate::handlers::messages::{compose_for, ComposeRequest};
use crate::metered::MeteredSpend;
use crate::state::{AppState, WsMessage};

/// Advertised on `/api/v1/status`.
pub const CAPABILITY: &str = konsensus_core::payloads::content::PORCH_READ_CAPABILITY;

/// How long a paid read waits for its bound reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    pub node_id: String,
    pub path: String,
    #[serde(default)]
    pub max_total_msat: Option<u64>,
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub node_id: String,
    pub path: String,
    pub status: PageStatus,
    pub content_type: String,
    pub body: String,
    /// What the read paid the node, msat.
    pub amount_msat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readmission_msat: Option<u64>,
    /// The paid kind-500 request.
    pub message_id: String,
    /// Set for a successful read of the card path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<CardView>,
}

#[derive(Debug, Serialize)]
pub struct CardView {
    pub card: FrontDoorCard,
    /// `bitsov://front-door#…`, also the QR payload.
    pub link: String,
    /// Within its lifetime and on this node's network.
    pub fresh: bool,
    /// The cache already held this node's card at an equal or higher `seq`
    /// and kept it (a rollback never replaces it).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

#[derive(Debug, Serialize)]
pub struct CardsResponse {
    pub cards: Vec<CardView>,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/browse/fetch", post(fetch))
        .route("/api/v1/browse/cards", get(cards))
}

/// One read in flight per (this node, peer). Freed on drop.
struct InFlight((NodeId, NodeId));

impl InFlight {
    fn set() -> &'static Mutex<HashSet<(NodeId, NodeId)>> {
        static SET: OnceLock<Mutex<HashSet<(NodeId, NodeId)>>> = OnceLock::new();
        SET.get_or_init(Default::default)
    }

    fn claim(ours: NodeId, peer: NodeId) -> Option<Self> {
        let mut set = Self::set().lock().unwrap_or_else(|e| e.into_inner());
        set.insert((ours, peer)).then_some(Self((ours, peer)))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        Self::set().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn view(card: FrontDoorCard, network: Option<&str>, stale: bool) -> Result<CardView, ApiError> {
    let now = now_unix();
    let fresh = match network {
        Some(net) => card.verify(now, net).is_ok(),
        None => card.expires_at > now,
    };
    let link = card
        .to_link()
        .map_err(|e| ApiError::Internal(format!("card link: {e}")))?;
    Ok(CardView { card, link, fresh, stale })
}

/// The plaintext of the kind-501 reply bound to `request` from `peer`. Only
/// envelopes the gate accepted reach the broadcast, and a reply-shaped one is
/// accepted only against our own outstanding paid request.
async fn bound_reply(
    replies: &mut broadcast::Receiver<Arc<WsMessage>>,
    peer: &NodeId,
    request: &MessageId,
) -> Option<String> {
    tokio::time::timeout(REPLY_TIMEOUT, async {
        loop {
            match replies.recv().await {
                Ok(m) if m.envelope.kind == KIND_PAGE_RESPONSE
                    && m.envelope.sender == *peer
                    && konsensus_core::is_web_service_reply(&m.envelope)
                    && m.envelope.references.contains(request) =>
                {
                    return m.plaintext.clone();
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// `POST /api/v1/browse/fetch` — one paid porch read.
async fn fetch(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    if !is_porch_path(&req.path) {
        return Err(ApiError::BadRequest(format!(
            "porch_path_invalid: {:?} is not {PORCH_CARD_PATH} or a flat .md/.txt page",
            req.path
        ))
        .with_reason("porch_path_invalid"));
    }
    let peer = NodeId::from_hex(&req.node_id)
        .map_err(|e| ApiError::BadRequest(format!("invalid node_id: {e}")))?;
    let ours = *state.identity.node_id();
    if peer == ours {
        return Err(ApiError::BadRequest("porch_own_node: this is your own node".into())
            .with_reason("porch_own_node"));
    }
    if !state.transport.is_connected(&peer).await {
        return Err(ApiError::Conflict(
            "porch_unreachable: not connected to this node; open its front door or add it as a contact".into(),
        )
        .with_reason("porch_unreachable"));
    }
    if !state.session_manager.has_session(&peer).await {
        return Err(ApiError::Conflict(
            "porch_knock_first: no E2EE session with this node; Knock (paid first contact) before reading its porch".into(),
        )
        .with_reason("porch_knock_first"));
    }
    let _slot = InFlight::claim(ours, peer).ok_or_else(|| {
        ApiError::Conflict("porch_busy: a read from this node is already in flight".into())
            .with_reason("porch_busy")
    })?;

    let request_id = uuid::Uuid::new_v4().to_string();
    let plaintext = serde_json::to_string(&PageRequest {
        request_id: request_id.clone(),
        path: req.path.clone(),
        method: "GET".into(),
        accept: vec!["text/markdown".into(), "text/plain".into()],
    })
    .map_err(|e| ApiError::Internal(format!("page request encode: {e}")))?;
    // Subscribe before paying, so a fast reply cannot slip past.
    let mut replies = state.ws_broadcast.subscribe();
    let Json(sent) = compose_for(
        auth,
        Arc::clone(&state),
        ComposeRequest {
            operation_id: None,
            wait_ack_ms: None,
            max_routing_fee_msat: req.max_routing_fee_msat,
            max_total_msat: req.max_total_msat,
            max_recipient_msat: None,
            recipient: req.node_id.clone(),
            is_room: false,
            kind: KIND_PAGE_REQUEST,
            plaintext,
            references: vec![],
        },
    )
    .await?;
    let paid = sent.amount_msat;
    let request = MessageId::from_hex(&sent.message_id)
        .map_err(|e| ApiError::Internal(format!("compose returned no message id: {e}")))?;

    let Some(text) = bound_reply(&mut replies, &peer, &request).await else {
        return Err(ApiError::Transport(format!(
            "porch_timeout: paid {paid} msat, no reply within {} s; not retried, a retry pays again",
            REPLY_TIMEOUT.as_secs()
        ))
        .with_reason("porch_timeout"));
    };
    let bad_reply = |what: String| {
        ApiError::Transport(format!("porch_reply_invalid: paid {paid} msat, {what}"))
            .with_reason("porch_reply_invalid")
    };
    let page: PageResponse =
        serde_json::from_str(&text).map_err(|e| bad_reply(format!("reply is not a page response: {e}")))?;
    if page.request_id != request_id {
        return Err(bad_reply("reply names another request".into()));
    }
    if page.body.len() > MAX_PORCH_BODY_BYTES {
        return Err(bad_reply(format!("body of {} bytes exceeds {MAX_PORCH_BODY_BYTES}", page.body.len())));
    }

    let card = if req.path == PORCH_CARD_PATH && page.status == PageStatus::Ok {
        let card = FrontDoorCard::parse(&page.body).map_err(|e| bad_reply(format!("card: {e}")))?;
        if card.node_id != peer.to_hex() {
            return Err(ApiError::Transport(format!(
                "porch_card_mismatch: paid {paid} msat, the node served a card for another node"
            ))
            .with_reason("porch_card_mismatch"));
        }
        let offer = state
            .front_door
            .known
            .lock()
            .await
            .offer(card.clone())
            .map_err(|e| bad_reply(format!("card: {e}")))?;
        Some(view(card, state.introduction.network.as_deref(), matches!(offer, Offer::Stale { .. }))?)
    } else {
        None
    };

    Ok(Json(FetchResponse {
        node_id: req.node_id,
        path: req.path,
        status: page.status,
        content_type: page.content_type,
        body: page.body,
        amount_msat: paid,
        readmission_msat: sent.readmission_msat,
        message_id: sent.message_id,
        card,
    }))
}

/// `GET /api/v1/browse/cards` — the verified cards this node holds.
async fn cards(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<CardsResponse>, ApiError> {
    let held = state.front_door.known.lock().await.list();
    let network = state.introduction.network.as_deref();
    let cards = held
        .into_iter()
        .map(|card| view(card, network, false))
        .collect::<Result<_, _>>()?;
    Ok(Json(CardsResponse { cards }))
}
