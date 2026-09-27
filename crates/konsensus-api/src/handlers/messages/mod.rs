//! Message endpoints — send, receive, query, and compose messages.
//!
//! The `compose` endpoint is the key integration point: the frontend sends
//! plaintext + recipient, and the node handles E2EE encryption, Lightning
//! payment, envelope construction, signing, and delivery. This keeps
//! crypto and payment logic out of the frontend (Principle 4: plaintext
//! only exists in the user's own node RAM).
//!
//! ## Submodules
//!
//! - [`send`] — `POST /api/v1/messages` (pre-encrypted message send)
//! - [`compose`] — `POST /api/v1/messages/compose` (node-side E2EE + payment)
//! - [`query`] — `GET /api/v1/messages`, `GET /api/v1/messages/:id`
//! - [`receive`] — incoming message processing types and helpers

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::metered::MeteredSpend;
use crate::error::ApiError;
use crate::state::AppState;

pub(crate) mod caps;
mod compose;
mod query;
mod receive;
mod resync;
mod send;

pub use compose::{create_payment_proof, ComposeRequest, ComposeResponse};
pub(crate) use compose::create_metered_payment_proof;
pub use query::{ListMessagesQuery, MessageResponse};
pub use send::{SendMessageRequest, SendMessageResponse};

// Membrane (N2), outbound side: a paid send this node refused before any
// payment left (price above the confirmed cap, budget grant exhausted) is a
// decision at the other node's door, recorded for the owner's own client.
// Observed here, around the handlers, so the send paths stay untouched.

async fn compose_observed(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ComposeRequest>,
) -> Result<Json<ComposeResponse>, ApiError> {
    let (recipient, kind, cap) = (req.recipient.clone(), req.kind, req.max_total_msat);
    let out = compose::compose_message(auth, State(Arc::clone(&state)), Json(req)).await;
    if let Err(e) = &out {
        state.audit_log.membrane().outbound_refused(e, &recipient, kind, cap);
    }
    out
}

async fn send_observed(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    let (recipient, kind, cap) = (req.recipient.clone(), req.kind, req.max_total_msat);
    let out = send::send_message(auth, State(Arc::clone(&state)), Json(req)).await;
    if let Err(e) = &out {
        state.audit_log.membrane().outbound_refused(e, &recipient, kind, cap);
    }
    out
}

/// Registers message routes for sending, composing, listing, reading, and deleting messages.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/messages", post(send_observed).get(query::list_messages))
        .route("/api/v1/messages/search", get(query::search_messages))
        .route("/api/v1/messages/compose", post(compose_observed))
        .route("/api/v1/messages/resync", post(resync::resync_messages))
        .route(
            "/api/v1/messages/:id",
            get(query::get_message).delete(query::delete_message),
        )
        .route(
            "/api/v1/messages/:id/plaintext",
            get(query::get_message_plaintext),
        )
}
