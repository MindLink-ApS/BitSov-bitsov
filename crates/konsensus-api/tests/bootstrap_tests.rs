//! Identity-free bootstrap: entry, the atomic transition, crash points, and
//! the router allowlist (#76, P1-1).
//!
//! Ports are never bound here: the router is driven with `tower::ServiceExt`
//! `oneshot`, and every data directory is a disposable temp dir.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

use konsensus_api::auth::{self, Scope};
use konsensus_api::bootstrap::{
    self, BootstrapState, CommitFault, DataDirLayout, DataDirProbe, StartupMode,
};
use konsensus_api::pairing::{self, PairingService};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn probe(dir: &std::path::Path) -> DataDirProbe {
    DataDirProbe::inspect(&DataDirLayout::new(dir)).unwrap()
}

fn empty_probe() -> DataDirProbe {
    DataDirProbe {
        marker_present: false,
        identity_material_present: false,
        wallet_or_channel_state_present: false,
        store_readable: true,
        stray_staging: Vec::new(),
    }
}

fn bootstrap_state(dir: &std::path::Path) -> Arc<BootstrapState> {
    let pairing = Arc::new(
        PairingService::open(dir, String::new(), false)
            .unwrap()
            .without_stdout_code(),
    );
    Arc::new(BootstrapState::new(DataDirLayout::new(dir), pairing))
}

// ─── Entry ─────────────────────────────────────────────────────────

#[test]
fn bootstrap_requires_all_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // The full conjunction holds: no marker, no identity, no state.
    assert_eq!(
        bootstrap::classify(&probe(tmp.path())),
        StartupMode::Bootstrap
    );

    // Breaking ANY clause takes bootstrap off the table. None of these is an
    // "almost empty" directory that gets the benefit of the doubt.
    for (label, p) in [
        (
            "marker present",
            DataDirProbe {
                marker_present: true,
                identity_material_present: true,
                ..empty_probe()
            },
        ),
        (
            "identity present",
            DataDirProbe {
                identity_material_present: true,
                ..empty_probe()
            },
        ),
        (
            "state present",
            DataDirProbe {
                wallet_or_channel_state_present: true,
                ..empty_probe()
            },
        ),
    ] {
        assert_ne!(
            bootstrap::classify(&p),
            StartupMode::Bootstrap,
            "{label} must not enter bootstrap"
        );
    }
}

#[test]
fn bootstrap_partial_state_refuses() {
    // Wallet/channel state with no identity is a DELETED KEY, not a fresh
    // install. The refusal must name the repair the operator should actually
    // run, and must not be answered by reopening first-run authority.
    let deleted_key = DataDirProbe {
        wallet_or_channel_state_present: true,
        ..empty_probe()
    };
    match bootstrap::classify(&deleted_key) {
        StartupMode::Refuse(r) => {
            assert_eq!(r.reason, "state_without_identity");
            assert!(
                r.repair.contains("konsensus restore"),
                "repair must name the restore command, got: {}",
                r.repair
            );
            assert!(r.detail.contains("DELETED KEY"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Identity material without a marker always requires operator repair.
    let interrupted = DataDirProbe {
        identity_material_present: true,
        ..empty_probe()
    };
    match bootstrap::classify(&interrupted) {
        StartupMode::Refuse(r) => {
            assert_eq!(r.reason, "identity_without_marker");
            assert!(
                r.repair.contains("konsensus repair mark-initialized"),
                "repair must name the repair command, got: {}",
                r.repair
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // An existing config is not permission to adopt a missing marker.
    let legacy = tempfile::tempdir().unwrap();
    std::fs::write(legacy.path().join("mnemonic.txt"), MNEMONIC).unwrap();
    std::fs::write(legacy.path().join("konsensus.toml"), "# existing config").unwrap();
    assert!(matches!(
        bootstrap::classify(&probe(legacy.path())),
        StartupMode::Refuse(_)
    ));
    assert!(!DataDirLayout::new(legacy.path()).marker().exists());
    assert_eq!(
        std::fs::read_to_string(legacy.path().join("mnemonic.txt")).unwrap(),
        MNEMONIC
    );

    // Positive control: explicit operator completion, not config presence,
    // permits startup once the initialization marker exists.
    std::fs::write(DataDirLayout::new(legacy.path()).marker(), "{}").unwrap();
    assert_eq!(
        bootstrap::classify(&probe(legacy.path())),
        StartupMode::Initialized
    );
}

#[test]
fn bootstrap_ignores_balance() {
    // Balance is not an authorization input. It is not a field of
    // `DataDirProbe`, so `classify` CANNOT consult it — the compiler enforces
    // that, and these two cases show the consequence at runtime.
    //
    // 1. An initialized node whose wallet holds nothing is still initialized:
    //    "fresh" is never "an existing identity with a zero balance".
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("mnemonic.txt"), MNEMONIC).unwrap();
    std::fs::write(tmp.path().join("NODE_INITIALIZED"), "{}").unwrap();
    // An empty wallet database: zero funds by any measure.
    std::fs::write(tmp.path().join("konsensus.db"), b"").unwrap();
    assert_eq!(
        bootstrap::classify(&probe(tmp.path())),
        StartupMode::Initialized,
        "an initialized node with no funds is initialized"
    );

    // 2. Conversely, an empty directory enters bootstrap regardless of what any
    //    balance source might claim, because nothing about funds is consulted.
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        bootstrap::classify(&probe(empty.path())),
        StartupMode::Bootstrap
    );
}

#[test]
fn initialized_missing_identity_or_corrupt_store_refuses() {
    // Marker present, mnemonic gone: a funded node with a deleted key.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("NODE_INITIALIZED"), "{}").unwrap();
    match bootstrap::classify(&probe(tmp.path())) {
        StartupMode::Refuse(r) => {
            assert_eq!(r.reason, "initialized_missing_identity");
            assert!(r.repair.contains("konsensus restore"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Marker and identity present, store unreadable: an operator repair.
    let tmp2 = tempfile::tempdir().unwrap();
    std::fs::write(tmp2.path().join("NODE_INITIALIZED"), "{}").unwrap();
    std::fs::write(tmp2.path().join("mnemonic.txt"), MNEMONIC).unwrap();
    std::fs::write(tmp2.path().join("konsensus.db"), b"this is not a database").unwrap();
    match bootstrap::classify(&probe(tmp2.path())) {
        StartupMode::Refuse(r) => {
            assert_eq!(r.reason, "initialized_store_corrupt");
            assert!(r.repair.contains("restore konsensus.db"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // POSITIVE CONTROL: a real SQLite header is accepted, so the refusal above
    // is about corruption and not about the check being broken.
    let tmp3 = tempfile::tempdir().unwrap();
    std::fs::write(tmp3.path().join("NODE_INITIALIZED"), "{}").unwrap();
    std::fs::write(tmp3.path().join("mnemonic.txt"), MNEMONIC).unwrap();
    std::fs::write(tmp3.path().join("konsensus.db"), b"SQLite format 3\0rest").unwrap();
    assert_eq!(
        bootstrap::classify(&probe(tmp3.path())),
        StartupMode::Initialized
    );
}

// ─── The transition ────────────────────────────────────────────────

#[test]
fn transition_marker_last() {
    // Stop the commit immediately after the atomic rename. The identity is in
    // place and the marker is NOT — which is the proof of ordering: if the
    // marker were written first or alongside, it would exist here.
    let tmp = tempfile::tempdir().unwrap();
    let layout = DataDirLayout::new(tmp.path());
    let err = bootstrap::commit_first_run_with_fault(
        &layout,
        MNEMONIC,
        None,
        CommitFault::AbortAfterRename,
    )
    .unwrap_err();
    assert!(matches!(err, bootstrap::CommitError::Aborted(_)), "{err}");

    assert!(
        layout.identity_dir().join("mnemonic.txt").exists(),
        "the rename must have happened"
    );
    assert!(
        !layout.marker().exists(),
        "the marker must be written LAST, after the rename"
    );

    // POSITIVE CONTROL: without the fault, both exist and the marker is the
    // sole signal that flips classification.
    let tmp2 = tempfile::tempdir().unwrap();
    let layout2 = DataDirLayout::new(tmp2.path());
    let outcome = bootstrap::commit_first_run(&layout2, MNEMONIC, None).unwrap();
    assert!(layout2.marker().exists());
    assert!(layout2.identity_dir().join("mnemonic.txt").exists());
    assert_eq!(
        outcome.identity_fingerprint,
        pairing::fingerprint_for_mnemonic(MNEMONIC).unwrap()
    );
    assert_eq!(
        bootstrap::classify(&probe(tmp2.path())),
        StartupMode::Initialized
    );
}

#[test]
fn crash_after_rename_before_marker_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = DataDirLayout::new(tmp.path());
    let _ = bootstrap::commit_first_run_with_fault(
        &layout,
        MNEMONIC,
        None,
        CommitFault::AbortAfterRename,
    );

    // Identity present, marker absent, no config file: this must REFUSE, and
    // never auto-reopen bootstrap — precisely the state an attacker would want
    // to induce.
    match bootstrap::classify(&probe(tmp.path())) {
        StartupMode::Refuse(r) => {
            assert_eq!(r.reason, "identity_without_marker");
            assert!(r.repair.contains("konsensus repair mark-initialized"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn crash_before_rename_ignores_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = DataDirLayout::new(tmp.path());
    let _ = bootstrap::commit_first_run_with_fault(
        &layout,
        MNEMONIC,
        None,
        CommitFault::AbortBeforeRename,
    );

    let p = probe(tmp.path());
    assert_eq!(
        p.stray_staging.len(),
        1,
        "the staging directory is reported"
    );
    assert!(
        !p.identity_material_present,
        "staging is not identity material"
    );
    assert!(!layout.identity_dir().exists());

    // Bootstrap is still legitimately open: no identity, no state. The staging
    // directory is reported and ignored — startup never consumes one.
    assert_eq!(bootstrap::classify(&p), StartupMode::Bootstrap);

    // And a later successful commit does not adopt the stray directory.
    let outcome = bootstrap::commit_first_run(&layout, MNEMONIC, None).unwrap();
    assert!(outcome.mnemonic_path.starts_with(layout.identity_dir()));
    assert_eq!(
        probe(tmp.path()).stray_staging.len(),
        1,
        "the stray staging directory is left for the operator, not consumed"
    );
}

#[test]
fn transition_single_flight_no_second_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let state = bootstrap_state(tmp.path());

    let mut results = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let state = Arc::clone(&state);
                scope.spawn(move || state.transition(MNEMONIC, CommitFault::None).is_ok())
            })
            .collect();
        for h in handles {
            results.push(h.join().unwrap());
        }
    });

    assert_eq!(
        results.iter().filter(|ok| **ok).count(),
        1,
        "exactly one transition may commit"
    );

    // The losers wrote nothing: no partial state, and no staging left behind.
    let p = probe(tmp.path());
    assert!(p.marker_present);
    assert!(p.identity_material_present);
    assert!(
        p.stray_staging.is_empty(),
        "a losing attempt must not leave staging behind: {:?}",
        p.stray_staging
    );
    assert_eq!(
        std::fs::read_to_string(
            DataDirLayout::new(tmp.path())
                .identity_dir()
                .join("mnemonic.txt")
        )
        .unwrap(),
        MNEMONIC
    );

    // A further attempt after the commit is a conflict, not a second write.
    assert!(state.transition(MNEMONIC, CommitFault::None).is_err());
}

#[tokio::test]
async fn bootstrap_tokens_invalid_after_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let state = bootstrap_state(tmp.path());
    let app = bootstrap::build_bootstrap_router(Arc::clone(&state));

    // Pair, then mint a bootstrap token through the real routes.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let pair_id = {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/pair/request")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"client_name": "app", "client_pubkey": pubkey})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The short code is a stdout tripwire and must never be in the response.
        assert!(json.get("short_code").is_none());
        assert!(json.get("challenge").is_none());
        json["pair_id"].as_str().unwrap().to_string()
    };

    let challenge_bytes =
        std::fs::read(state.pairing.dir().join(format!("challenge-{pair_id}"))).unwrap();
    assert_eq!(challenge_bytes.len(), 32);
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &pair_id,
            &pubkey,
            &challenge_bytes,
        ))
        .to_bytes(),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pair/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"pair_id": pair_id, "signature": sig}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let confirmed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = confirmed["client_id"].as_str().unwrap().to_string();

    let challenge = state.pairing.issue_token_challenge(&client_id).unwrap();
    let token_sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let issued = state
        .pairing
        .issue_bootstrap_token(&state.jwt_secret, &client_id, &challenge, &token_sig)
        .unwrap();

    // POSITIVE CONTROL: the token works on the bootstrap router while
    // bootstrap is open — first-run restore is PROTECTED, not open.
    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/identity/restore")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"mnemonic": MNEMONIC}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unauth.status(),
        StatusCode::UNAUTHORIZED,
        "first-run restore must require a bootstrap pairing"
    );

    assert!(auth::validate_token(&issued.token, &state.jwt_secret).is_ok());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/identity/restore")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", issued.token))
                .body(Body::from(
                    serde_json::json!({"mnemonic": MNEMONIC}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The commit happened. Now the live node's secret is identity-derived.
    let identity = konsensus_core::NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
    let live_secret = hex::encode(identity.derive_jwt_secret());
    assert!(
        auth::validate_token(&issued.token, &live_secret).is_err(),
        "a bootstrap token must stop verifying the instant the identity-derived secret takes over"
    );

    // Second, independent gate: even re-signed with the live secret, a token
    // marked `bst` is refused — `PairingBinding::from_claims` rejects the empty
    // identity fingerprint a bootstrap token carries.
    let claims = auth::validate_token(&issued.token, &state.jwt_secret).unwrap();
    assert_eq!(claims.bst, Some(true));
    assert!(auth::PairingBinding::from_claims(&claims).is_err());

    // Pairings survive, REBOUND: stamped with the committed identity and
    // stripped of first-run `identity` authority.
    let fingerprint = pairing::fingerprint_for_mnemonic(MNEMONIC).unwrap();
    let durable = state.pairing.reload_from_disk().unwrap();
    assert_eq!(durable.clients.len(), 1);
    assert_eq!(durable.clients[0].identity_fingerprint, fingerprint);
    assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());
    assert!(
        !durable.clients[0].scopes.contains(&Scope::Identity),
        "first-run identity authority must not survive the commit"
    );

    // A second first-run restore does not produce a second identity. It does
    // not even get as far as the single-flight conflict: the pairing was
    // rebound to the committed identity, so the bootstrap token's binding no
    // longer matches anything and it fails authentication outright. Bootstrap
    // authority has ended permanently for this data directory.
    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/identity/restore")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", issued.token))
                .body(Body::from(
                    serde_json::json!({"mnemonic": MNEMONIC}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    // The effect: exactly one identity, and it is the one that was committed.
    assert_eq!(
        std::fs::read_to_string(
            DataDirLayout::new(tmp.path())
                .identity_dir()
                .join("mnemonic.txt")
        )
        .unwrap(),
        MNEMONIC
    );
}

#[tokio::test]
async fn bootstrap_router_allowlist() {
    let tmp = tempfile::tempdir().unwrap();
    let state = bootstrap_state(tmp.path());
    let app = bootstrap::build_bootstrap_router(Arc::clone(&state));

    // FORBIDDEN, and deliberately UNROUTED rather than scope-denied. A node
    // with no keys cannot pay, and mounting these to return 403 would
    // manufacture exactly the "looks like a funded node" surface the design
    // warns about. 404 says the capability genuinely does not exist yet.
    let forbidden: &[(&str, &str)] = &[
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/payments/balance"),
        ("POST", "/api/v1/payments/send"),
        ("GET", "/api/v1/messages"),
        ("POST", "/api/v1/messages/compose"),
        ("GET", "/api/v1/peers"),
        ("POST", "/api/v1/peers/import"),
        ("GET", "/api/v1/peers/export"),
        ("POST", "/api/v1/gossip/publish"),
        ("GET", "/api/v1/invites"),
        ("GET", "/api/v1/export/bundle"),
        ("GET", "/api/v1/content"),
        ("GET", "/api/v1/calendar"),
        ("POST", "/api/v1/identity/mnemonic"),
        ("GET", "/api/v1/ws"),
        ("GET", "/api/v1/rooms"),
        ("POST", "/api/v1/auth/local"),
        ("GET", "/metrics"),
        // Elevation write paths do not exist anywhere over HTTP, bootstrap
        // included.
        ("POST", "/api/v1/pair/grant"),
        ("POST", "/api/v1/identity/replacement-approve"),
    ];
    for (method, path) in forbidden {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{method} {path} must be absent from the bootstrap router, not merely denied"
        );
    }

    // EFFECT ASSERTION: none of those calls created any durable state.
    let durable = state.pairing.reload_from_disk().unwrap();
    assert!(durable.clients.is_empty());
    assert!(durable.grants.is_empty());
    assert!(!DataDirLayout::new(tmp.path()).marker().exists());
    assert!(!tmp.path().join("mnemonic.txt").exists());

    // POSITIVE CONTROLS: the permitted surface answers.
    for (method, path, body) in [
        ("GET", "/livez", ""),
        ("GET", "/api/v1/bootstrap/state", ""),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{method} {path} must be reachable"
        );
    }

    let key = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pair/request")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"client_name": "app", "client_pubkey": pubkey}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the ceremony must be reachable in bootstrap"
    );
}
