//! `front_door`: the narrow scope that lets a paired app publish the owner's
//! front-door card without `admin`.
//!
//! Driven over the real router with real paired tokens. Every refusal checks
//! the effect (no card written, no grant written) and sits beside a positive
//! control, so the suite cannot pass by refusing everything.

#![allow(dead_code)]

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::auth::{self, Scope};
use konsensus_api::control::{self, ControlContext, ControlRequest, ControlResponse};
use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::pairing::{self, PairingError, PairingService};
use konsensus_api::spend_budget::GrantTerms;
use konsensus_api::state::AppState;

use common::*;

struct Fx {
    state: Arc<AppState>,
    service: Arc<PairingService>,
    console: OwnerConsole,
    key: SigningKey,
    client_id: String,
    tmp: tempfile::TempDir,
}

fn open(
    dir: &std::path::Path,
    fingerprint: &str,
    console: &OwnerConsole,
    owner_run: bool,
) -> Arc<PairingService> {
    Arc::new(
        PairingService::open(dir, fingerprint.to_string(), owner_run)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    )
}

fn fixture() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let fingerprint = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let console = OwnerConsole::default();
    let service = open(tmp.path(), &fingerprint, &console, true);
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        introduction: IntroductionSettings {
            network: Some("regtest".into()),
            endpoint: Some("127.0.0.1:9735".into()),
        },
        data_dir: Some(tmp.path().to_path_buf()),
        ..(*base).clone()
    });
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &outcome.pair_id,
            &pubkey,
            &challenge,
        ))
        .to_bytes(),
    );
    let client = service
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap();
    Fx {
        state,
        service,
        console,
        key,
        client_id: client.client_id,
        tmp,
    }
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = body
        .map(|b| Body::from(b.to_string()))
        .unwrap_or_else(Body::empty);
    let response = test_router(state.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})),
    )
}

impl Fx {
    fn control(&self) -> ControlContext {
        ControlContext {
            service: Arc::clone(&self.service),
            identity_fingerprint: self.service.bound_fingerprint(),
            data_dir: self.tmp.path().to_path_buf(),
            mnemonic_path: self.tmp.path().join("mnemonic.txt"),
            replacement_guard: control::ReplacementGuard {
                layout: konsensus_api::bootstrap::DataDirLayout::new(self.tmp.path()),
                uses_identity_derived_keys: false,
                has_identity_passphrase: false,
            },
        }
    }

    /// A freshly issued paired token (carries whatever grant is live now).
    async fn token(&self) -> (String, Vec<String>) {
        let challenge = self.service.issue_token_challenge(&self.client_id).unwrap();
        let sig = hex::encode(self.key.sign(challenge.as_bytes()).to_bytes());
        let (status, body) = call(
            &self.state,
            "POST",
            "/api/v1/pair/token",
            Some(json!({"client_id": self.client_id, "challenge": challenge, "signature": sig})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let scopes = body["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        (body["token"].as_str().unwrap().to_string(), scopes)
    }

    async fn ask(&self, body: Value) -> (StatusCode, Value) {
        let (read, _) = self.token().await;
        call(
            &self.state,
            "POST",
            "/api/v1/pair/elevation-request",
            Some(body),
            Some(&read),
        )
        .await
    }

    fn phrase(&self, op_id: &str) -> String {
        let pending = self
            .service
            .snapshot()
            .pending_elevations
            .into_iter()
            .find(|e| e.op_id == op_id)
            .unwrap();
        self.console
            .confirmation(&pairing::grant_confirmation_phrase(&pending))
    }

    /// The app asks for `front_door`; the owner grants it with the console code.
    async fn grant_front_door(&self) -> String {
        let (status, op) = self.ask(json!({"scopes": ["front_door"]})).await;
        assert_eq!(status, StatusCode::OK, "{op}");
        assert!(
            op["owner_action"]
                .as_str()
                .unwrap()
                .starts_with("konsensus grant --op "),
            "{op}"
        );
        let op_id = op["op_id"].as_str().unwrap().to_string();
        let resp = control::handle(
            &self.control(),
            ControlRequest::GrantFrontDoor {
                confirmation: self.phrase(&op_id),
                op_id: op_id.clone(),
                ttl_secs: 600,
            },
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }), "{resp:?}");
        op_id
    }

    async fn publish(&self, token: &str, name: &str) -> (StatusCode, Value) {
        call(
            &self.state,
            "PUT",
            "/api/v1/front-door",
            Some(json!({"display_name": name})),
            Some(token),
        )
        .await
    }

    async fn card_seq(&self) -> Option<u64> {
        self.state
            .front_door
            .card
            .lock()
            .await
            .as_ref()
            .map(|c| c.seq)
    }
}

#[tokio::test]
async fn paired_app_without_the_grant_gets_403_and_writes_no_card() {
    let fx = fixture();
    let (token, scopes) = fx.token().await;
    assert_eq!(scopes, ["read", "receive"]);
    let (status, body) = fx.publish(&token, "Ada").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("front_door"), "{body}");
    assert_eq!(
        fx.card_seq().await,
        None,
        "a refused publish must not sign a card"
    );
}

#[tokio::test]
async fn owner_granted_front_door_lets_the_paired_app_publish() {
    let fx = fixture();
    let op_id = fx.grant_front_door().await;
    let (token, scopes) = fx.token().await;
    assert_eq!(
        scopes,
        ["read", "receive", "front_door"],
        "front_door only: no spend, no admin"
    );
    let (status, body) = fx.publish(&token, "Ada").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["card"]["seq"], 1);
    assert_eq!(fx.card_seq().await, Some(1));

    // The request reads as granted, and the durable record is a front-door
    // grant, never a spend grant.
    let (read, _) = fx.token().await;
    let (_, status) = call(
        &fx.state,
        "GET",
        &format!("/api/v1/pair/elevation/{op_id}"),
        None,
        Some(&read),
    )
    .await;
    assert_eq!(status["status"], "granted", "{status}");
    let durable = fx.service.reload_from_disk().unwrap();
    assert!(durable.grants.is_empty(), "no spend grant may appear");
    assert_eq!(durable.front_door_grants.len(), 1);
    assert_eq!(durable.front_door_grants[0].granted_by, "cli");
    assert!(
        fx.service.grant_view_for(&fx.client_id).is_none(),
        "the spend view stays empty"
    );
}

#[tokio::test]
async fn front_door_opens_no_other_route() {
    let fx = fixture();
    fx.grant_front_door().await;
    let (paired, _) = fx.token().await;
    let bare = auth::create_token(
        &fx.state.identity.node_id().to_hex(),
        &fx.state.jwt_secret,
        vec![Scope::FrontDoor],
    )
    .unwrap();
    // Representative admin (configuration) and spend (money) routes.
    let routes: &[(&str, &str)] = &[
        ("POST", "/api/v1/peers"),
        ("POST", "/api/v1/peers/import"),
        ("POST", "/api/v1/gossip/publish"),
        ("PUT", "/api/v1/content/pages/index.html"),
        ("POST", "/api/v1/invites"),
        ("POST", "/api/v1/payments/pay"),
        ("POST", "/api/v1/payments/keysend"),
        ("POST", "/api/v1/messages/compose"),
        ("POST", "/api/v1/pair/window"),
    ];
    for token in [&paired, &bare] {
        for (method, uri) in routes {
            let (status, body) = call(&fx.state, method, uri, Some(json!({})), Some(token)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {uri} must refuse front_door: {body}"
            );
        }
    }
    // Positive control: the same bare token publishes.
    let (status, body) = fx.publish(&bare, "Ada").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn admin_still_publishes_and_read_or_receive_do_not() {
    let fx = fixture();
    let node = fx.state.identity.node_id().to_hex();
    for scopes in [
        vec![Scope::Read],
        vec![Scope::Read, Scope::Receive],
        vec![Scope::Spend],
    ] {
        let token = auth::create_token(&node, &fx.state.jwt_secret, scopes.clone()).unwrap();
        let (status, _) = fx.publish(&token, "Ada").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{scopes:?}");
    }
    let admin = auth::create_token(&node, &fx.state.jwt_secret, vec![Scope::Admin]).unwrap();
    let (status, body) = fx.publish(&admin, "Ada").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn revoking_stops_the_next_publish() {
    let fx = fixture();
    fx.grant_front_door().await;
    let (token, _) = fx.token().await;
    assert_eq!(fx.publish(&token, "Ada").await.0, StatusCode::OK);

    let resp = control::handle(
        &fx.control(),
        ControlRequest::RevokeGrant {
            client_id: Some(fx.client_id.clone()),
        },
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }), "{resp:?}");
    let (status, body) = fx.publish(&token, "Mallory").await;
    assert!(
        !status.is_success(),
        "a revoked grant must not publish: {status} {body}"
    );
    assert_eq!(fx.card_seq().await, Some(1), "the card is unchanged");
    let (_, scopes) = fx.token().await;
    assert_eq!(scopes, ["read", "receive"]);
    assert!(fx
        .service
        .reload_from_disk()
        .unwrap()
        .front_door_grants
        .is_empty());

    // An epoch bump (pair-revoke --keep-pairing) drops a fresh grant too.
    fx.grant_front_door().await;
    fx.service.bump_epoch(&fx.client_id).unwrap();
    assert!(fx
        .service
        .reload_from_disk()
        .unwrap()
        .front_door_grants
        .is_empty());
}

#[tokio::test]
async fn a_front_door_request_is_alone_and_carries_no_budget() {
    let fx = fixture();
    let (status, body) = fx.ask(json!({"scopes": ["spend", "front_door"]})).await;
    assert!(status.is_client_error(), "{status} {body}");
    let (status, body) = fx
        .ask(json!({"scopes": ["front_door"], "budget": {"budget_msat": 1000}}))
        .await;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(fx
        .service
        .reload_from_disk()
        .unwrap()
        .pending_elevations
        .is_empty());

    // A front-door request cannot be granted as spend, and a spend request
    // cannot be granted as front_door. Nothing is written either way.
    let (_, fd) = fx.ask(json!({"scopes": ["front_door"]})).await;
    let fd = fd["op_id"].as_str().unwrap().to_string();
    let err = fx
        .service
        .grant_elevation(&fd, &fx.phrase(&fd), GrantTerms::new(1_000_000))
        .unwrap_err();
    assert!(matches!(err, PairingError::NotGrantable(_)), "{err}");
    let (_, sp) = fx.ask(json!({"scopes": ["spend"]})).await;
    let sp = sp["op_id"].as_str().unwrap().to_string();
    let err = fx
        .service
        .grant_front_door(&sp, &fx.phrase(&sp), 600)
        .unwrap_err();
    assert!(matches!(err, PairingError::NotGrantable(_)), "{err}");
    // A wrong phrase writes nothing; the window is capped at 24 h.
    assert!(fx.service.grant_front_door(&fd, "yes", 600).is_err());
    assert!(fx
        .service
        .grant_front_door(&fd, &fx.phrase(&fd), 24 * 3600 + 1)
        .is_err());
    let durable = fx.service.reload_from_disk().unwrap();
    assert!(durable.grants.is_empty() && durable.front_door_grants.is_empty());
    // Positive control: the right pairing of request and grant works.
    fx.service
        .grant_front_door(&fd, &fx.phrase(&fd), 600)
        .unwrap();
    assert_eq!(
        fx.service
            .reload_from_disk()
            .unwrap()
            .front_door_grants
            .len(),
        1
    );
}

#[tokio::test]
async fn front_door_and_spend_grants_do_not_replace_each_other() {
    let fx = fixture();
    let (_, sp) = fx.ask(json!({"scopes": ["spend"]})).await;
    let sp = sp["op_id"].as_str().unwrap().to_string();
    fx.service
        .grant_elevation(&sp, &fx.phrase(&sp), GrantTerms::new(1_000_000))
        .unwrap();
    fx.grant_front_door().await;
    let (_, scopes) = fx.token().await;
    assert_eq!(scopes, ["read", "receive", "spend", "front_door"]);
    // And a new spend window leaves the front-door grant alone.
    let (_, sp2) = fx.ask(json!({"scopes": ["spend"]})).await;
    let sp2 = sp2["op_id"].as_str().unwrap().to_string();
    fx.service
        .grant_elevation(&sp2, &fx.phrase(&sp2), GrantTerms::new(2_000_000))
        .unwrap();
    let (_, scopes) = fx.token().await;
    assert!(scopes.contains(&"front_door".to_string()), "{scopes:?}");
    assert_eq!(
        fx.service
            .grant_view_for(&fx.client_id)
            .unwrap()
            .budget_msat,
        2_000_000
    );
}

#[tokio::test]
async fn a_sidecar_never_honours_a_front_door_grant() {
    let fx = fixture();
    fx.grant_front_door().await;
    // The packaged app reopens the same data directory without an owner socket.
    let sidecar = open(
        fx.tmp.path(),
        &fx.service.bound_fingerprint(),
        &fx.console,
        false,
    );
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&sidecar)),
        ..(*fx.state).clone()
    });
    let fx = Fx {
        state,
        service: sidecar,
        ..fx
    };
    let (token, scopes) = fx.token().await;
    assert_eq!(scopes, ["read", "receive"]);
    assert_eq!(fx.publish(&token, "Ada").await.0, StatusCode::FORBIDDEN);
    let (status, op) = fx.ask(json!({"scopes": ["front_door"]})).await;
    assert_eq!(status, StatusCode::OK, "{op}");
    assert!(
        op["owner_action"]
            .as_str()
            .unwrap()
            .starts_with("unavailable"),
        "{op}"
    );
}

#[test]
fn the_owner_is_shown_a_front_door_request_as_exactly_that() {
    let fx = fixture();
    let op = fx
        .service
        .create_elevation_request(&fx.client_id, vec![Scope::FrontDoor])
        .unwrap();
    match control::handle(
        &fx.control(),
        ControlRequest::Describe {
            op_id: op.op_id.clone(),
        },
    ) {
        ControlResponse::Describe {
            summary,
            front_door,
            proposed_terms,
            ..
        } => {
            assert!(front_door);
            assert!(proposed_terms.is_none());
            assert!(
                summary.contains("FRONT DOOR PUBLISH REQUEST")
                    && summary.contains("moves no value"),
                "{summary}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(!pairing::default_pairing_scopes().contains(&Scope::FrontDoor));
    assert!(!Scope::loopback_only().contains(&Scope::FrontDoor));
}

#[tokio::test]
async fn a_request_that_died_in_a_restart_reads_lost_and_asking_again_works() {
    let fx = fixture();
    let (status, op) = fx.ask(json!({"scopes": ["front_door"]})).await;
    assert_eq!(status, StatusCode::OK, "{op}");
    let op_id = op["op_id"].as_str().unwrap().to_string();
    let (read, _) = fx.token().await;
    let path = format!("/api/v1/pair/elevation/{op_id}");
    let (_, before) = call(&fx.state, "GET", &path, None, Some(&read)).await;
    assert_eq!(before["status"], "pending", "{before}");

    // Restart the node over the same data directory, now started with a config.
    let fingerprint = fx.service.bound_fingerprint();
    let console = OwnerConsole::default();
    let service = Arc::new(
        PairingService::open(fx.tmp.path(), fingerprint, true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code()
            .with_owner_config("/Users/owner/bitsov/konsensus.toml".into()),
    );
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        ..(*fx.state).clone()
    });
    let restarted = Fx { state, service, console, ..fx };

    let (read, _) = restarted.token().await;
    let (_, after) = call(&restarted.state, "GET", &path, None, Some(&read)).await;
    assert_eq!(after["status"], "lost", "{after}");
    assert_eq!(after["owner_confirmation_required"], false, "{after}");

    // Asking again: a live request, and the owner command names the config.
    let (status, again) = restarted.ask(json!({"scopes": ["front_door"]})).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    let again_id = again["op_id"].as_str().unwrap();
    assert_eq!(
        again["owner_action"],
        format!("konsensus grant --op {again_id} --config /Users/owner/bitsov/konsensus.toml")
    );
    let code = restarted.console.owner_code(again_id);
    assert!(!again.to_string().contains(&code), "the app never sees the code");
    let (_, live) = call(
        &restarted.state,
        "GET",
        &format!("/api/v1/pair/elevation/{again_id}"),
        None,
        Some(&read),
    )
    .await;
    assert_eq!(live["status"], "pending", "{live}");
    assert!(!live.to_string().contains(&code));
}
