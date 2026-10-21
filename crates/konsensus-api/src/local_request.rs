//! Header admission for routes that grant trust to loopback connections.

use std::net::SocketAddr;

use axum::{
    extract::{Extension, Request},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

/// Installed by the local router, using the actual API listener address.
#[derive(Clone)]
pub(crate) struct LocalRequestPolicy {
    authorities: Vec<String>,
    browser_origins: Vec<HeaderValue>,
}

impl LocalRequestPolicy {
    pub(crate) fn new(addr: SocketAddr, browser_origins: Vec<HeaderValue>) -> Self {
        let port = addr.port();
        let mut authorities = vec![
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
        ];
        if !addr.ip().is_unspecified() {
            authorities.push(addr.to_string());
        }
        // HTTP clients and browsers omit the default port from Host and Origin.
        // Derive aliases only from the configured authorities, never the request.
        if port == 80 {
            let portless = authorities
                .iter()
                .filter_map(|authority| authority.strip_suffix(":80").map(str::to_owned))
                .collect::<Vec<_>>();
            authorities.extend(portless);
        }
        Self {
            authorities,
            browser_origins,
        }
    }

    pub(crate) fn validate(&self, headers: &HeaderMap) -> Result<(), LocalRequestRejection> {
        // Never use forwarded headers, DNS resolution, or a request-derived port
        // to decide what is trusted. Exactly one Host must match a configured value.
        let mut hosts = headers.get_all(header::HOST).iter();
        let valid_host = hosts
            .next()
            .and_then(|host| host.to_str().ok())
            .is_some_and(|host| {
                self.authorities
                    .iter()
                    .any(|allowed| host.eq_ignore_ascii_case(allowed))
            });
        if !valid_host || hosts.next().is_some() {
            return Err(forbidden(
                "local_host_forbidden",
                "Host is not an allowed local API authority",
            ));
        }

        let mut origins = headers.get_all(header::ORIGIN).iter();
        if let Some(origin) = origins.next() {
            let valid_origin = origin.to_str().ok().is_some_and(|value| {
                is_web_origin(value)
                    && (self.authorities.iter().any(|authority| {
                        value.eq_ignore_ascii_case(&format!("http://{authority}"))
                    }) || self.browser_origins.iter().any(|allowed| origin == allowed))
            });
            if !valid_origin || origins.next().is_some() {
                return Err(forbidden(
                    "local_origin_forbidden",
                    "Origin is not an allowed local API browser origin",
                ));
            }
        }
        Ok(())
    }
}

fn is_web_origin(value: &str) -> bool {
    let Ok(uri) = value.parse::<Uri>() else {
        return false;
    };
    let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return false;
    };
    matches!(scheme, "http" | "https")
        && !authority.as_str().contains('@')
        && value == format!("{scheme}://{authority}")
}

/// Small rejection value; construct the HTTP response only at the boundary.
pub(crate) struct LocalRequestRejection {
    code: &'static str,
    error: &'static str,
}

impl IntoResponse for LocalRequestRejection {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": self.code,
                "error": self.error,
            })),
        )
            .into_response()
    }
}

fn forbidden(code: &'static str, error: &'static str) -> LocalRequestRejection {
    LocalRequestRejection { code, error }
}

pub(crate) async fn guard(
    Extension(policy): Extension<LocalRequestPolicy>,
    request: Request,
    next: Next,
) -> Result<Response, LocalRequestRejection> {
    policy.validate(request.headers())?;
    Ok(next.run(request).await)
}
