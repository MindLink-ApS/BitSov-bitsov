//! Home-only box page. Its router must live on a separate LAN listener.
//! No signing keys or seed/password serializers are reachable from this surface.
use super::BootstrapState;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::time::Instant;

const MAX_BODY_BYTES: usize = 2048;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOURCES: usize = 1024;
const SOURCE_IDLE_TTL: Duration = Duration::from_secs(60);

struct Bucket {
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    fn take(&mut self, now: Instant, burst: f64, per_second: f64) -> bool {
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * per_second).min(burst);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
struct SourceBuckets {
    reads: Bucket,
    posts: Bucket,
    last_seen: Instant,
}

#[derive(Default)]
struct SetupRateLimits(Mutex<HashMap<IpAddr, SourceBuckets>>);
impl SetupRateLimits {
    fn allow(&self, ip: IpAddr, post: bool) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let mut sources = self.0.lock().unwrap();
        let now = Instant::now();
        if !sources.contains_key(&ip) && sources.len() >= MAX_SOURCES {
            // Only reclaim idle entries after both buckets could fully refill.
            // Never evict an active source and thereby grant it a fresh burst.
            sources.retain(|_, source| now.duration_since(source.last_seen) < SOURCE_IDLE_TTL);
            if sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let source = sources.entry(ip).or_insert_with(|| SourceBuckets {
            reads: Bucket {
                tokens: 8.0,
                updated: now,
            },
            posts: Bucket {
                tokens: 4.0,
                updated: now,
            },
            last_seen: now,
        });
        source.last_seen = now;
        if post {
            source.posts.take(now, 4.0, 0.2)
        } else {
            source.reads.take(now, 8.0, 2.0)
        }
    }
}

/// Deliberately opaque: ticket failures must not echo secret link material.
#[derive(Debug, thiserror::Error)]
#[error("setup ticket unavailable")]
pub struct SetupTicketError;

/// The daemon and page share one ticket authority, including cancellation.
pub trait SetupTickets: Send + Sync {
    /// Replace the one-use ticket. The caller bounds TTL to the boot window.
    fn mint(&self, ttl: Duration) -> Result<String, SetupTicketError>;
    /// Invalidate the ticket and revoke the pre-commit bootstrap pairing atomically.
    fn cancel(&self) -> Result<(), SetupTicketError>;
}
struct Session {
    cookie: String,
    csrf: String,
}
/// Only the `--home` node launcher constructs this separate surface.
pub struct SetupPage {
    bootstrap: Option<Arc<BootstrapState>>,
    tickets: Option<Arc<dyn SetupTickets>>,
    hosts: Vec<String>,
    label: String,
    status: Mutex<String>,
    sessions: Mutex<VecDeque<Session>>,
    rate_limits: SetupRateLimits,
}
impl SetupPage {
    /// Exact HTTP authorities include the actual listener port; never trust forwarded headers.
    pub fn new(
        bootstrap: Option<Arc<BootstrapState>>,
        tickets: Option<Arc<dyn SetupTickets>>,
        hosts: Vec<String>,
        label: String,
        status: String,
    ) -> Self {
        Self {
            bootstrap,
            tickets,
            hosts,
            label,
            status: Mutex::new(status),
            sessions: Mutex::new(VecDeque::new()),
            rate_limits: SetupRateLimits::default(),
        }
    }
    /// Status-only runtime transition, without adding authority routes to the main API.
    pub fn set_status(&self, status: &str) {
        *self.status.lock().unwrap() = status.into();
    }
    fn active(&self) -> bool {
        self.bootstrap.as_ref().is_some_and(|b| !b.is_committed())
    }
    fn open(&self) -> Result<&BootstrapState, StatusCode> {
        let b = self
            .bootstrap
            .as_deref()
            .filter(|b| !b.is_committed())
            .ok_or(StatusCode::CONFLICT)?;
        if b.sas_started_at.elapsed() >= Duration::from_secs(900) {
            return Err(StatusCode::GONE);
        }
        if b.sas_failures.load(Ordering::SeqCst) >= 3 {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(b)
    }
    fn csrf(&self, headers: &HeaderMap) -> bool {
        let Some(cookie) = headers
            .get(header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| {
                s.split(';')
                    .find_map(|s| s.trim().strip_prefix("bitsov_setup="))
            })
        else {
            return false;
        };
        let Some(csrf) = headers.get("x-csrf-token").and_then(|h| h.to_str().ok()) else {
            return false;
        };
        self.sessions.lock().unwrap().iter().any(|s| {
            bool::from(s.cookie.as_bytes().ct_eq(cookie.as_bytes()))
                && bool::from(s.csrf.as_bytes().ct_eq(csrf.as_bytes()))
        })
    }
}
/// RFC1918, IPv4 link-local, IPv6 link-local/ULA; exclude both Tailscale ranges.
pub fn lan_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => lan_source(IpAddr::V4(ip)),
            None => {
                (ip.is_unique_local() || ip.is_unicast_link_local())
                    && ip.segments()[..3] != [0xfd7a, 0x115c, 0xa1e0]
            }
        },
    }
}
async fn guard(State(page): State<Arc<SetupPage>>, request: Request, next: Next) -> Response {
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip());
    let source_ok = source.is_some_and(lan_source);
    let host_ok = request.headers().get_all(header::HOST).iter().count() == 1
        && request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| page.hosts.iter().any(|own| own.eq_ignore_ascii_case(h)));
    let mut response = if !source_ok
        || !host_ok
        || (request.method() != axum::http::Method::GET && !page.csrf(request.headers()))
    {
        StatusCode::FORBIDDEN.into_response()
    } else if !source.is_some_and(|ip| {
        page.rate_limits
            .allow(ip, request.method() == axum::http::Method::POST)
    }) {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        response
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        );
    }
    response
}

/// Read every body before entering a handler, including routes without extractors.
/// This is an absolute deadline, so trickling chunks cannot keep a slot occupied.
async fn read_body(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let read = Bytes::from_request(Request::from_parts(parts.clone(), body), &());
    let mut response = match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(Ok(bytes)) => {
            return next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Ok(Err(rejection)) => rejection.into_response(),
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}
fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
async fn index(State(page): State<Arc<SetupPage>>) -> Response {
    if !page.active() || page.open().is_err() {
        let state = if page.active() {
            "Setup closed. Restart the box to try again.".into()
        } else if page.bootstrap.as_ref().is_some_and(|b| b.is_committed()) {
            "Setup complete. Starting your box…".into()
        } else {
            page.status.lock().unwrap().clone()
        };
        let fingerprint = page
            .bootstrap
            .as_ref()
            .map(|b| b.pairing.bound_fingerprint())
            .unwrap_or_default();
        return Html(format!("<!doctype html><meta charset=utf-8><title>BitSov box</title><h1>{}</h1><p>{}</p><p>{}</p><p>Use the BitSov app.</p>",escape(&page.label),escape(&state),escape(&fingerprint))).into_response();
    }
    let session = Session {
        cookie: random(),
        csrf: random(),
    };
    let csrf = session.csrf.clone();
    let cookie = format!(
        "bitsov_setup={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=900",
        session.cookie
    );
    {
        let mut sessions = page.sessions.lock().unwrap();
        if sessions.len() == 32 {
            sessions.pop_front();
        }
        sessions.push_back(session);
    }
    let html = include_str!("setup.html")
        .replace("__NONCE__", &csrf)
        .replace("__LABEL__", &escape(&page.label));
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    response.headers_mut().insert("content-security-policy",HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{csrf}'; style-src 'nonce-{csrf}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" )).unwrap());
    response
}
#[derive(Serialize)]
struct View {
    state: &'static str,
    seconds: u64,
    device_name: Option<String>,
    claimed_at: Option<i64>,
    ceremony_id: Option<String>,
    sas_digest: Option<String>,
    words: Option<[String; 4]>,
    approved: bool,
}
async fn view(
    State(page): State<Arc<SetupPage>>,
    headers: HeaderMap,
) -> Result<Json<View>, StatusCode> {
    if !page.csrf(&headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    let b = page.open()?;
    let pending = b.pending.lock().unwrap();
    let p = pending.as_ref().filter(|p| !p.expired());
    let sas = p.and_then(|p| p.sas.as_ref());
    let client = b.pairing.list_clients().into_iter().next();
    Ok(Json(View {
        state: if p.is_some() || client.is_some() {
            "claimed"
        } else {
            "setup"
        },
        seconds: 900u64.saturating_sub(b.sas_started_at.elapsed().as_secs()),
        claimed_at: client.as_ref().map(|c| c.created_at),
        device_name: sas
            .map(|s| s.device_name.clone())
            .or_else(|| client.map(|c| c.name)),
        ceremony_id: sas.and(p).map(|p| p.ceremony_id.clone()),
        sas_digest: sas.map(|s| s.digest.to_hex().to_string()),
        words: sas.map(|s| crate::sas::words(&s.digest).map(str::to_owned)),
        approved: sas.is_some_and(|s| s.box_approved),
    }))
}
#[derive(Serialize)]
struct Ticket {
    uri: String,
    qr: String,
    expires_in: u64,
}
async fn start(State(page): State<Arc<SetupPage>>) -> Result<Json<Ticket>, StatusCode> {
    let b = page.open()?;
    let _transition = b.transition.lock().unwrap();
    page.open()?;
    if b.pending.lock().unwrap().is_some() || !b.pairing.list_clients().is_empty() {
        return Err(StatusCode::CONFLICT);
    }
    let ttl = Duration::from_secs(300)
        .min(Duration::from_secs(900).saturating_sub(b.sas_started_at.elapsed()));
    let uri = page
        .tickets
        .as_ref()
        .ok_or(StatusCode::CONFLICT)?
        .mint(ttl)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let code =
        qrcode::QrCode::new(uri.as_bytes()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let width = code.width();
    let mut qr = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"Pairing QR\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path fill=\"black\" d=\"",width+8,width+8);
    for y in 0..width {
        for x in 0..width {
            if code[(x, y)] == qrcode::Color::Dark {
                use std::fmt::Write;
                let _ = write!(qr, "M{} {}h1v1h-1z", x + 4, y + 4);
            }
        }
    }
    qr.push_str("\"/></svg>");
    Ok(Json(Ticket {
        uri,
        qr,
        expires_in: ttl.as_secs(),
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    ceremony_id: String,
    sas_digest: String,
}
async fn approve(
    State(page): State<Arc<SetupPage>>,
    Json(body): Json<Approval>,
) -> Result<StatusCode, StatusCode> {
    let b = page.open()?;
    let _transition = b.transition.lock().unwrap();
    page.open()?;
    let mut pending = b.pending.lock().unwrap();
    let p = pending
        .as_mut()
        .filter(|p| !p.expired() && p.ceremony_id == body.ceremony_id)
        .ok_or(StatusCode::CONFLICT)?;
    let sas = p.sas.as_mut().ok_or(StatusCode::CONFLICT)?;
    let digest = blake3::Hash::from_hex(&body.sas_digest).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !bool::from(digest.as_bytes().ct_eq(sas.digest.as_bytes())) {
        return Err(StatusCode::BAD_REQUEST);
    }
    sas.box_approved = true;
    Ok(StatusCode::NO_CONTENT)
}
async fn cancel(State(page): State<Arc<SetupPage>>) -> Result<StatusCode, StatusCode> {
    let b = page.open()?;
    let _transition = b.transition.lock().unwrap();
    page.open()?;
    page.tickets
        .as_ref()
        .ok_or(StatusCode::CONFLICT)?
        .cancel()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *b.pending.lock().unwrap() = None;
    b.sas_failures.fetch_add(1, Ordering::SeqCst);
    Ok(StatusCode::NO_CONTENT)
}
/// No CORS middleware and no API routes, owner grants, registration or signing routes.
pub fn router(page: Arc<SetupPage>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/setup/state", get(view))
        .route("/setup/start", post(start))
        .route("/setup/approve", post(approve))
        .route("/setup/cancel", post(cancel))
        .layer(middleware::from_fn(read_body))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(page.clone(), guard))
        .with_state(page)
}
#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
