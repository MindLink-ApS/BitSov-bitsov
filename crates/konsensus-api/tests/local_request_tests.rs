//! Exercise header admission on real routes, including its shared local-read use.
mod common;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use common::test_state;
use konsensus_api::{auth, build_router_for_addr};
use tower::ServiceExt;

#[tokio::test]
async fn local_auth_accepts_allowed_hosts_origins_and_native_clients() {
    let state = test_state();
    let app = build_router_for_addr(state.clone(), "192.0.2.10:4321".parse().unwrap());
    // Five successful mints fit the route's process-global quota. These also
    // prove the port and additional host come from configuration, not the request.
    for (host, origin, peer) in [
        ("localhost:4321", None, "127.0.0.1:1000"),
        ("127.0.0.1:4321", None, "127.0.0.1:1000"),
        ("[::1]:4321", Some("http://[::1]:4321"), "[::1]:1000"),
        ("192.0.2.10:4321", None, "127.0.0.1:1000"),
        (
            "LOCALHOST:4321",
            Some("http://localhost:4321"),
            "127.0.0.1:1000",
        ),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/local")
            .header("host", host)
            .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{host} {origin:?}");
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims =
            auth::validate_token(json["token"].as_str().unwrap(), &state.jwt_secret).unwrap();
        assert_eq!(claims.scp, vec![auth::Scope::Read, auth::Scope::Receive]);
    }
}

#[tokio::test]
async fn local_routes_reject_untrusted_missing_and_ambiguous_headers() {
    for listen in ["0.0.0.0:4321", "[::]:4321"] {
        let app = build_router_for_addr(test_state(), listen.parse().unwrap());
        for path in [
            "/api/v1/auth/local",
            "/api/v1/energy",
            "/api/v1/membrane",
            "/api/v1/ws",
        ] {
            let cases = [
                (vec![], vec![], "local_host_forbidden"),
                (
                    vec!["attacker.example:4321"],
                    vec![],
                    "local_host_forbidden",
                ),
                (vec!["localhost:3141"], vec![], "local_host_forbidden"),
                (vec!["localhost"], vec![], "local_host_forbidden"),
                (
                    vec!["localhost:4321", "localhost:4321"],
                    vec![],
                    "local_host_forbidden",
                ),
                (
                    vec!["localhost:4321,attacker.example:4321"],
                    vec![],
                    "local_host_forbidden",
                ),
                (
                    vec!["localhost.attacker.example:4321"],
                    vec![],
                    "local_host_forbidden",
                ),
                (vec!["user@localhost:4321"], vec![], "local_host_forbidden"),
                (vec!["::1:4321"], vec![], "local_host_forbidden"),
                (vec!["0.0.0.0:4321"], vec![], "local_host_forbidden"),
                (vec!["[::]:4321"], vec![], "local_host_forbidden"),
                (
                    vec!["localhost:4321"],
                    vec!["https://attacker.example"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["null"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:4321", "http://localhost:4321"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:4321/"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:4321/path"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:4321?x"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:4321#x"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://user@localhost:4321"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["https://localhost:4321"],
                    "local_origin_forbidden",
                ),
                (
                    vec!["localhost:4321"],
                    vec!["http://localhost:3141"],
                    "local_origin_forbidden",
                ),
            ];
            for (hosts, origins, code) in cases {
                let mut request = Request::builder()
                    .method(if path.ends_with("auth/local") {
                        "POST"
                    } else {
                        "GET"
                    })
                    .uri(path)
                    .header("x-forwarded-host", "localhost:4321")
                    .header("forwarded", "host=localhost:4321")
                    .header("remote_tunnel_identity", "paired-client")
                    .header("x-bitsov-proxy-auth", "paired-client")
                    .extension(ConnectInfo("127.0.0.1:1000".parse::<SocketAddr>().unwrap()));
                for host in &hosts {
                    request = request.header("host", *host);
                }
                for origin in &origins {
                    request = request.header("origin", *origin);
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{path} {hosts:?} {origins:?}"
                );
                let body = to_bytes(response.into_body(), 4096).await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["code"], code, "{path} {hosts:?} {origins:?}");
                assert!(json.get("token").is_none());
            }
        }
    }
}

/// Exercise the production remote stack with real TCP peer metadata. Register
/// the bridge before sending bytes, just as the Noise tunnel does.
#[tokio::test]
async fn remote_tunnel_observability_reaches_pairing_and_scope_auth() {
    use konsensus_api::{
        pairing::{self, PairingService},
        rate_limit::{remote_tunnel_identity, RemoteTunnelClients},
        sas::NoiseBinding,
        AppState, RateLimiter,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let base = test_state();
    let pairing = Arc::new(
        PairingService::open(
            dir.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            false,
        )
        .unwrap()
        .without_stdout_code(),
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let client = pairing
        .create_verified_remote_pairing(
            "remote-test",
            &hex::encode(key.verifying_key().to_bytes()),
            &[72; 32],
        )
        .unwrap();
    let state = Arc::new(AppState {
        pairing: Some(pairing.clone()),
        ..(*base).clone()
    });
    let paired_token = |scopes| {
        auth::create_paired_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            scopes,
            &client.client_id,
            client.epoch,
            &pairing.bound_fingerprint(),
        )
        .unwrap()
    };
    let read_token = paired_token(vec![auth::Scope::Read]);
    let no_read_token = paired_token(vec![auth::Scope::Receive]);
    let unpaired_token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        vec![auth::Scope::Read],
    )
    .unwrap();
    let tunnels = Arc::new(RemoteTunnelClients::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router =
        konsensus_api::build_remote_router_with_limiter(state, Arc::new(RateLimiter::new(10_000)))
            .layer(axum::middleware::from_fn_with_state(
                tunnels.clone(),
                remote_tunnel_identity,
            ));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Both registration forms carry the private tunnel marker; only the Noise
    // form additionally carries the transcript used by enrollment routes.
    for noise in [false, true] {
        for (token, expected) in [
            (None, 401),
            (Some("invalid-jwt"), 401),
            (Some(unpaired_token.as_str()), 403),
            (Some(no_read_token.as_str()), 403),
            (Some(read_token.as_str()), 200),
        ] {
            for path in ["/api/v1/energy", "/api/v1/membrane", "/api/v1/ws"] {
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let peer = stream.local_addr().unwrap();
                let _registration = if noise {
                    tunnels.register_noise(
                        peer,
                        client.client_id.clone(),
                        NoiseBinding {
                            handshake_hash: [73; 32],
                            box_public_key: pairing.box_transport_pubkey(),
                            client_static: [72; 32],
                        },
                    )
                } else {
                    tunnels.register(peer, client.client_id.clone())
                };
                let ws = path.ends_with("/ws");
                let authorization = match token {
                    Some(token) if ws => {
                        format!("Sec-WebSocket-Protocol: bitsov.v1, bitsov.jwt.{token}\r\n")
                    }
                    Some(token) => format!("Authorization: Bearer {token}\r\n"),
                    None => String::new(),
                };
                let connection = if ws {
                    "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                } else {
                    "Connection: close\r\n"
                };
                // The app's proxy port need not match the internal listener.
                stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:45678\r\n{connection}{authorization}\r\n").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    while !response.ends_with(b"\r\n\r\n") {
                        response.push(stream.read_u8().await.unwrap());
                        assert!(response.len() < 8192);
                    }
                })
                .await
                .unwrap();
                let status: u16 = std::str::from_utf8(&response)
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse()
                    .unwrap();
                let expected = if ws && expected == 200 { 101 } else { expected };
                assert_eq!(status, expected, "{path}, noise={noise}");
            }
        }
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn loopback_without_policy_or_tunnel_marker_still_fails_closed() {
    let app = konsensus_api::build_remote_router(test_state());
    for path in ["/api/v1/energy", "/api/v1/membrane", "/api/v1/ws"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "localhost:3141")
                    .header("remote_tunnel_identity", "paired-client")
                    .header("x-bitsov-proxy-auth", "paired-client")
                    .extension(ConnectInfo("127.0.0.1:1000".parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn local_read_accepts_configured_browser_origins_only_when_cors_enabled() {
    // Exercise the same guard without minting more JWTs from the shared quota.
    for cors_enabled in [false, true] {
        let state = Arc::new(konsensus_api::AppState {
            cors_enabled,
            ..(*test_state()).clone()
        });
        let app = build_router_for_addr(state, "127.0.0.1:4321".parse().unwrap());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/energy")
                    .header("host", "localhost:4321")
                    .header("origin", "http://localhost:1420")
                    .extension(ConnectInfo("127.0.0.1:1000".parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // With an allowed browser origin admission reaches the JWT check.
        assert_eq!(
            response.status(),
            if cors_enabled {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
}
