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
