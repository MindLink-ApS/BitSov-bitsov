//! Local observability is available only to a currently paired read client.
//! Connection metadata comes from the listener, never proxy/user headers.

use crate::{
    auth::scoped::{Read, ScopedAuth},
    AppState,
};
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc};

/// Proof of an admitted loopback connection: either a registered tunnel bridge
/// or a local request passing Host/Origin policy. Missing metadata fails closed
/// (including routers mounted without ConnectInfo). This does not grant auth.
pub(crate) struct LocalConnection;

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for LocalConnection {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Response> {
        match parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            Some(ConnectInfo(addr)) if addr.ip().is_loopback() => {
                // The remote router has no local Host/Origin policy: the app's
                // proxy authority differs from the internal listener. Only the
                // server-owned marker from remote_tunnel_identity admits that
                // bridge here; JWT, live pairing and read scope still apply.
                if parts
                    .extensions
                    .get::<crate::rate_limit::RemotePairingRateLimitKey>()
                    .is_some()
                {
                    return Ok(Self);
                }
                let policy = parts
                    .extensions
                    .get::<crate::local_request::LocalRequestPolicy>()
                    .ok_or_else(|| {
                        (StatusCode::FORBIDDEN, "local API policy required").into_response()
                    })?;
                policy
                    .validate(&parts.headers)
                    .map_err(IntoResponse::into_response)?;
                Ok(Self)
            }
            _ => Err((StatusCode::FORBIDDEN, "local paired read required").into_response()),
        }
    }
}

/// Enforces both locality and the live pairing binding before reading data.
pub(crate) struct LocalPairedRead;

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for LocalPairedRead {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Response> {
        LocalConnection::from_request_parts(parts, state).await?;
        let auth = ScopedAuth::<Read>::from_request_parts(parts, state).await?;
        if auth.pairing.is_none() {
            return Err((StatusCode::FORBIDDEN, "local paired read required").into_response());
        }
        Ok(Self)
    }
}
