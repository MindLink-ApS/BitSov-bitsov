//! Legacy unbound invite routes — **removed**.
//!
//! `POST /api/v1/invite` and `POST /api/v1/invite/redeem` issued/redeemed a
//! base58 `InviteToken` with no invitee binding (symmetric peer-add). That
//! path is superseded by invitee-bound [`crate::handlers::invites`]
//! (`POST /api/v1/invites` + `POST /api/v1/invites/accept`, `BitSovInvite`).
//!
//! These URLs still exist so leftover clients get a clear **410 Gone** with a
//! successor `Link`, not a silent 404. See `docs/v2/ADR-029-invite-token-scheme.md`
//! and `docs/v2/LEGACY-INTRO-AND-INVITE-MIGRATION.md`.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;

/// Successor for issue (bound invite creation).
const SUCCESSOR_ISSUE: &str = "</api/v1/invites>; rel=\"successor-version\"";
/// Successor for redeem/accept.
const SUCCESSOR_ACCEPT: &str = "</api/v1/invites/accept>; rel=\"successor-version\"";

fn gone(successor_link: &'static str, detail: &'static str) -> Response {
    (
        StatusCode::GONE,
        [
            (header::HeaderName::from_static("deprecation"), "true"),
            (header::LINK, successor_link),
        ],
        Json(json!({
            "error": "legacy_invite_removed",
            "code": "legacy_invite_removed",
            "message": detail,
            "use": if successor_link.contains("accept") {
                "POST /api/v1/invites/accept with a BitSovInvite (bitsov://…)"
            } else {
                "POST /api/v1/invites to issue a BitSovInvite bound to the invitee"
            },
        })),
    )
        .into_response()
}

async fn legacy_invite_gone() -> Response {
    tracing::warn!(deprecated = true, removed = true, route = "/api/v1/invite", "legacy InviteToken issue called");
    gone(
        SUCCESSOR_ISSUE,
        "POST /api/v1/invite (unbound InviteToken) has been removed. Issue an invitee-bound BitSovInvite via POST /api/v1/invites.",
    )
}

async fn legacy_redeem_gone() -> Response {
    tracing::warn!(deprecated = true, removed = true, route = "/api/v1/invite/redeem", "legacy InviteToken redeem called");
    gone(
        SUCCESSOR_ACCEPT,
        "POST /api/v1/invite/redeem (unbound InviteToken) has been removed. Accept a BitSovInvite via POST /api/v1/invites/accept.",
    )
}

/// Registers the removed legacy invite URLs (410 Gone only).
pub fn routes() -> Router<std::sync::Arc<crate::state::AppState>> {
    Router::new()
        .route("/api/v1/invite", post(legacy_invite_gone))
        .route("/api/v1/invite/redeem", post(legacy_redeem_gone))
}
