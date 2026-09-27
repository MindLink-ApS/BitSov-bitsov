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

/// Proof that the listener identified the caller as loopback. Missing metadata
/// fails closed (including routers mounted without ConnectInfo).
pub(crate) struct LocalConnection;

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for LocalConnection {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Response> {
        match parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            Some(ConnectInfo(addr)) if addr.ip().is_loopback() => Ok(Self),
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
