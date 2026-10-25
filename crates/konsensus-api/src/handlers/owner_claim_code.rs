//! Owner-authenticated display of the box claim code for app onboarding.
//!
//! Mounted only on the owner-local API router, never on the remote tunnel
//! router or any peer surface. The code reaches a caller only when the
//! request comes from loopback, carries a live token, and that token is either
//! a local console session or a pairing holding an enrolled owner device key.
//! The code is never written to tracing or the audit log.
use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State},
    http::{header::CACHE_CONTROL, HeaderValue},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    auth::scoped::{Read, ScopedAuth},
    error::ApiError,
    pairing::device::ClaimWindow,
    rate_limit::{AuthenticatedNoise, RateLimiter, RemotePairingRateLimitKey},
    state::AppState,
};

/// Displays per minute per owner actor. Reading the code is a rare, manual
/// step of adding a device, so a human pace is ample.
const CLAIM_CODE_READS_PER_MINUTE: u32 = 5;

fn limiter() -> &'static RateLimiter {
    static LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        RateLimiter::with_window(
            CLAIM_CODE_READS_PER_MINUTE,
            std::time::Duration::from_secs(60),
        )
    })
}

/// `GET /api/v1/owner/claim-code` body. Carries the code only in `open`.
#[derive(Serialize)]
pub(crate) struct ClaimCodeView {
    /// `open`, `claimed`, `closed` or `unavailable`.
    pub state: &'static str,
    /// The 18-character claim code, only while a claim-bound enrollment waits for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Zeroizing<String>>,
    /// Unix seconds after which the pending enrollment no longer accepts the code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Label the enrolling device gave itself; it proves nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// The owner-local console session or an enrolled owner device, by actor key.
fn owner_actor(auth: &ScopedAuth<Read>, state: &AppState) -> Result<String, ApiError> {
    let Some(binding) = auth.pairing.as_ref() else {
        // Issued at the loopback control surface or by the node key itself.
        return Ok(format!("console:{}", auth.node_id));
    };
    let service = state.pairing.as_ref().ok_or_else(|| {
        ApiError::Forbidden("this pairing has no enrolled owner device".into())
            .with_reason("owner_device_required")
    })?;
    service
        .owner_device_for(&binding.client_id, binding.epoch)
        .map_err(|_| {
            ApiError::Forbidden("this pairing has no enrolled owner device".into())
                .with_reason("owner_device_required")
        })?;
    Ok(format!("device:{}", binding.client_id))
}

fn view(state: &AppState) -> ClaimCodeView {
    let closed = ClaimCodeView {
        state: "closed",
        code: None,
        expires_at: None,
        device_name: None,
    };
    let Some(dir) = state.data_dir.as_deref() else {
        return ClaimCodeView {
            state: "unavailable",
            ..closed
        };
    };
    if !crate::sas::required(dir) {
        return ClaimCodeView {
            state: "unavailable",
            ..closed
        };
    }
    let window = state
        .pairing
        .as_ref()
        .map_or(ClaimWindow::Claimed, |p| p.claim_window());
    match window {
        ClaimWindow::Closed => closed,
        ClaimWindow::Claimed => ClaimCodeView {
            state: "claimed",
            ..closed
        },
        ClaimWindow::Open {
            expires_at,
            device_name,
        } => {
            // A malformed or unreadable file fails closed, without echoing bytes.
            let Ok(code) = crate::sas::load(dir) else {
                return ClaimCodeView {
                    state: "unavailable",
                    ..closed
                };
            };
            let mut bytes = Zeroizing::new(Vec::with_capacity(18));
            if code.write_local(&mut *bytes).is_err() {
                return ClaimCodeView {
                    state: "unavailable",
                    ..closed
                };
            }
            let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
            ClaimCodeView {
                state: "open",
                code: Some(text),
                expires_at: Some(expires_at),
                device_name: Some(device_name),
            }
        }
    }
}

/// `GET /api/v1/owner/claim-code`.
///
/// Refused for any tunnel-bridged request (the route is also absent from the
/// remote router), any non-loopback source, and any pairing without an
/// enrolled owner device. Rate limited per actor. Always `no-store`.
pub(crate) async fn show(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    noise: Option<Extension<AuthenticatedNoise>>,
    tunnel: Option<Extension<RemotePairingRateLimitKey>>,
) -> Result<Response, ApiError> {
    if noise.is_some() || tunnel.is_some() {
        return Err(ApiError::Forbidden(
            "the claim code is shown only at the owner console".into(),
        )
        .with_reason("owner_console_only"));
    }
    if !connect_info.is_some_and(|peer| peer.0.ip().is_loopback()) {
        return Err(ApiError::Forbidden(
            "the claim code is shown only at the owner console".into(),
        )
        .with_reason("owner_console_only"));
    }
    let actor = owner_actor(&auth, &state)?;
    if !limiter().check_key(&format!("claim-code:{actor}")) {
        return Err(ApiError::TooManyRequests(
            "claim code display rate limit exceeded; retry in a minute".into(),
        ));
    }
    let view = view(&state);
    // The audit record names the actor and outcome, never the code.
    state.audit_log.record(
        "owner.claim_code_viewed",
        &actor,
        Some(serde_json::json!({"state": view.state})),
    );
    let mut response = Json(view).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
