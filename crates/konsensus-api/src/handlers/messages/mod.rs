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

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

mod compose;
mod query;
mod receive;
mod resync;
mod send;

pub use compose::{create_payment_proof, ComposeRequest, ComposeResponse};
pub use query::{ListMessagesQuery, MessageResponse};
pub use send::{SendMessageRequest, SendMessageResponse};

/// Registers message routes for sending, composing, listing, reading, and deleting messages.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/messages", post(send::send_message).get(query::list_messages))
        .route("/api/v1/messages/compose", post(compose::compose_message))
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
