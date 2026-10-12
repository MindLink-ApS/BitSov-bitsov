//! Owner approval must require a separate enrolled device and its own tunnel.
#![allow(dead_code)]
mod common;
#[path = "common/owner_console.rs"]
mod owner_console;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    pairing::{self, PairedClient, PairingService},
    state::AppState,
};
use owner_console::OwnerConsole;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
struct Fixture {
    dir: tempfile::TempDir,
    state: Arc<AppState>,
    svc: Arc<PairingService>,
    owner: PairedClient,
    requester: PairedClient,
    owner_token: String,
    token: String,
    device: EcdsaKeyPair,
    key_id: String,
}
impl Fixture {
    fn new(home: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = test_state();
        let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
        let root = konsensus_core::OwnerApprovalKey::from_mnemonic(MNEMONIC, "", &[9; 32]).unwrap();
        let console = OwnerConsole::default();
        let svc = PairingService::open(dir.path(), fp.clone(), true)
            .unwrap()
            .with_owner_approval_key(root.verifying_key())
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code();
        let owner_signing = SigningKey::from_bytes(&[91; 32]);
        let requesting = SigningKey::from_bytes(&[81; 32]);
        let owner = svc
            .create_ticket_remote_pairing(
                "owner",
                &hex::encode(owner_signing.verifying_key().to_bytes()),
                &[92; 32],
            )
            .unwrap();
        let requester = svc
            .create_ticket_remote_pairing(
                "requester",
                &hex::encode(requesting.verifying_key().to_bytes()),
                &[82; 32],
            )
            .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let device =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public = hex::encode(device.public_key().as_ref());
        let message = pairing::device::registration_message(&fp, &owner.client_id, &public);
        let proof = hex::encode(device.sign(&rng, message.as_bytes()).unwrap().as_ref());
        let op = svc
            .request_device_key(&owner.client_id, &public, "owner", &proof)
            .unwrap();
        let key = svc
            .approve_device_key(
                &op.op_id,
                &console.owner_code(&op.op_id),
                &hex::encode(
                    root.sign(
                        pairing::device::owner_approval_message(
                            &fp,
                            &owner.client_pubkey,
                            owner.epoch,
                            &public,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
                ),
            )
            .unwrap();
        drop(svc);
        let mut svc = PairingService::open(dir.path(), fp, !home)
            .unwrap()
            .with_owner_approval_key(root.verifying_key())
            .without_stdout_code();
        if home {
            svc = svc.with_local_owner_device();
        }
        let svc = Arc::new(svc);
        let token_for = |c: &PairedClient, k: &SigningKey| {
            let challenge = svc.issue_token_challenge(&c.client_id).unwrap();
            svc.issue_token(
                &base.identity.node_id().to_hex(),
                &base.jwt_secret,
                &c.client_id,
                &challenge,
                &hex::encode(k.sign(challenge.as_bytes()).to_bytes()),
            )
            .unwrap()
            .token
        };
        let owner_token = token_for(&owner, &owner_signing);
        let token = token_for(&requester, &requesting);
        let state = Arc::new(AppState {
            pairing: Some(svc.clone()),
            data_dir: Some(dir.path().into()),
            audit_log: Arc::new(
                konsensus_api::audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
            ),
            ..(*base).clone()
        });
        Self {
            dir,
            state,
            svc,
            owner,
            requester,
            owner_token,
            token,
            device,
            key_id: key.key_id,
        }
    }
    fn sign(&self, message: &str) -> String {
        hex::encode(
            self.device
                .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
                .unwrap()
                .as_ref(),
        )
    }
    async fn call(
        &self,
        owner: bool,
        noise: bool,
        method: &str,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        use konsensus_api::rate_limit::{remote_tunnel_identity, RemoteTunnelClients};
        let tunnels = Arc::new(RemoteTunnelClients::default());
        let peer = "127.0.0.1:40001".parse().unwrap();
        let client = if owner { &self.owner } else { &self.requester };
        let _guard = if noise {
            tunnels.register_noise(
                peer,
                client.client_id.clone(),
                konsensus_api::sas::NoiseBinding {
                    handshake_hash: [93; 32],
                    box_public_key: self.svc.box_transport_pubkey(),
                    client_static: if owner { [92; 32] } else { [82; 32] },
                },
            )
        } else {
            tunnels.register(peer, client.client_id.clone())
        };
        let router = konsensus_api::build_remote_router_with_limiter(
            self.state.clone(),
            Arc::new(konsensus_api::rate_limit::RateLimiter::new(10_000)),
        )
        .layer(axum::middleware::from_fn_with_state(
            tunnels,
            remote_tunnel_identity,
        ))
        .layer(axum::extract::connect_info::MockConnectInfo(peer));
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            if owner {
                                &self.owner_token
                            } else {
                                &self.token
                            }
                        ),
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(json!(null)),
        )
    }
    async fn request(&self, owner: bool) -> Value {
        let (status, body) = self.call(owner, true, "POST", "/api/v1/pair/approval-request", json!({"kind":"spend_grant", "terms":{"budget_msat":100000,"per_call_max_msat":10000,"window_secs":600}})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
    async fn approve(
        &self,
        op: &Value,
        signature: String,
        owner: bool,
        noise: bool,
    ) -> (StatusCode, Value) {
        self.call(
            owner,
            noise,
            "POST",
            &format!(
                "/api/v1/pair/approval/{}/approve",
                op["op_id"].as_str().unwrap()
            ),
            json!({"approver_key_id":self.key_id,"signature":signature}),
        )
        .await
    }
}
#[tokio::test]
async fn pending_grants_nothing_then_separate_owner_approves_once_in_both_modes() {
    for home in [false, true] {
        let f = Fixture::new(home);
        let op = f.request(false).await;
        assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
        let sig = f.sign(op["approval_message"].as_str().unwrap());
        assert_eq!(
            f.approve(&op, sig.clone(), true, true).await.0,
            StatusCode::OK
        );
        assert!(f.svc.grant_view_for(&f.requester.client_id).is_some());
        assert_ne!(f.approve(&op, sig, true, true).await.0, StatusCode::OK);
    }
}
#[tokio::test]
async fn self_approval_and_borrowed_key_and_missing_noise_grant_nothing() {
    let f = Fixture::new(true);
    let own = f.request(true).await;
    assert_eq!(
        f.approve(
            &own,
            f.sign(own["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let op = f.request(false).await;
    let sig = f.sign(op["approval_message"].as_str().unwrap());
    assert_eq!(
        f.approve(&op, sig.clone(), false, true).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.approve(&op, sig, true, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
    assert!(f.svc.grant_view_for(&f.owner.client_id).is_none());
}
#[tokio::test]
async fn wrong_node_tampered_terms_revoked_key_and_stale_epoch_are_refused() {
    let f = Fixture::new(true);
    let op = f.request(false).await;
    let message = op["approval_message"].as_str().unwrap();
    for tampered in [
        message.replace(&f.svc.bound_fingerprint(), "wrong-node"),
        message.replace("budget_msat:100000", "budget_msat:99999"),
        message.replace("nonce:", "nonce:00"),
    ] {
        assert_eq!(
            f.approve(&op, f.sign(&tampered), true, true).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
    }
    f.svc
        .revoke_device_key(&f.key_id, Some(&f.owner.client_id))
        .unwrap();
    assert_eq!(
        f.approve(&op, f.sign(message), true, true).await.0,
        StatusCode::FORBIDDEN
    );
    let f = Fixture::new(true);
    let op = f.request(false).await;
    f.svc.bump_epoch(&f.owner.client_id).unwrap();
    assert_ne!(
        f.approve(
            &op,
            f.sign(op["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
}
#[tokio::test]
async fn request_limit_discovery_status_and_strict_pr_a_kinds() {
    let f = Fixture::new(true);
    let op = f.request(false).await;
    let path = format!("/api/v1/pair/approval/{}", op["op_id"].as_str().unwrap());
    let (status, view) = f.call(false, true, "GET", &path, json!(null)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["approval_message"], op["approval_message"]);
    assert_ne!(
        f.call(true, true, "GET", &path, json!(null)).await.0,
        StatusCode::OK
    );
    let pending = format!(
        "/api/v1/pair/approvals/pending?approver_key_id={}",
        f.key_id
    );
    let (status, view) = f.call(true, true, "GET", &pending, json!(null)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        view["pending"][0]["approval_message"],
        op["approval_message"]
    );
    assert_eq!(
        f.call(false, true, "GET", &pending, json!(null)).await.0,
        StatusCode::FORBIDDEN
    );
    f.request(false).await;
    f.request(false).await;
    assert_eq!(f.call(false, true, "POST", "/api/v1/pair/approval-request", json!({"kind":"spend_grant", "terms":{"budget_msat":100000,"per_call_max_msat":10000,"window_secs":600}})).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_ne!(
        f.call(
            false,
            true,
            "POST",
            "/api/v1/pair/approval-request",
            json!({"kind":"breaker_reset","terms":{}})
        )
        .await
        .0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn first_contact_is_bounded_and_consumed_once_in_home_and_console_modes() {
    for home in [true, false] {
        let f = Fixture::new(home);
        let spend = f.request(false).await;
        let (status, body) = f
            .approve(
                &spend,
                f.sign(spend["approval_message"].as_str().unwrap()),
                true,
                true,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let request = |max| json!({"kind":"first_contact","terms":{"recipient":PEER,"max_total_msat":max,"budget_msat":50000}});
        let (status, op) = f
            .call(
                false,
                true,
                "POST",
                "/api/v1/pair/approval-request",
                request(1000),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{op}");
        assert!(f
            .svc
            .take_first_contact(&f.requester.client_id, f.requester.epoch, PEER)
            .is_none());
        assert_eq!(
            f.approve(
                &op,
                f.sign(op["approval_message"].as_str().unwrap()),
                true,
                true
            )
            .await
            .0,
            StatusCode::OK
        );
        let _grant = f
            .svc
            .take_first_contact(&f.requester.client_id, f.requester.epoch, PEER)
            .unwrap();
        assert!(f
            .svc
            .take_first_contact(&f.requester.client_id, f.requester.epoch, PEER)
            .is_none());
        let (status, op) = f
            .call(
                false,
                true,
                "POST",
                "/api/v1/pair/approval-request",
                request(10001),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = f
            .approve(
                &op,
                f.sign(op["approval_message"].as_str().unwrap()),
                true,
                true,
            )
            .await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(f
            .svc
            .take_first_contact(&f.requester.client_id, f.requester.epoch, PEER)
            .is_none());
    }
}

#[tokio::test]
async fn replay_across_requests_and_replaced_grant_are_refused_and_audited_without_signatures() {
    let f = Fixture::new(true);
    let a = f.request(false).await;
    let b = f.request(false).await;
    let signature = f.sign(a["approval_message"].as_str().unwrap());
    assert_eq!(
        f.approve(&b, signature.clone(), true, true).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.approve(&a, signature.clone(), true, true).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.approve(
            &b,
            f.sign(b["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let audit = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("pair.owner_approved"));
    assert!(audit.contains("pair.owner_approval_refused"));
    assert!(audit.contains("spend_grant"));
    assert!(audit.contains(&f.key_id));
    assert!(!audit.contains(&signature));
    assert!(!audit.contains(&f.owner_token));
    assert!(!audit.contains(&f.token));
    assert!(!audit.contains(a["nonce"].as_str().unwrap()));
}
#[tokio::test]
async fn approval_message_binds_every_displayed_field_and_rejects_unknown_terms() {
    let f = Fixture::new(true);
    let op = f.request(false).await;
    let expected=format!("bitsov-owner-approval-v1\nnode:{}\nkind:spend_grant\nclient:{}\nclient_pubkey:{}\nepoch:{}\ngrant_op:-\nrecipient:-\nmax_total_msat:100000\nbudget_msat:100000\nper_call_max_msat:10000\nwindow_secs:600\nop_id:{}\nnonce:{}\nexpires_at:{}", f.svc.bound_fingerprint(),f.requester.client_id,f.requester.client_pubkey,f.requester.epoch,op["op_id"].as_str().unwrap(),op["nonce"].as_str().unwrap(),op["expires_at"]);
    assert_eq!(op["approval_message"], expected);
    assert_eq!(op["nonce"].as_str().unwrap().len(), 32);
    let now = chrono::Utc::now().timestamp();
    assert!((299..=300).contains(&(op["expires_at"].as_i64().unwrap() - now)));
    for extra in ["client_id", "nonce", "breakers", "allow_liquidity_fees"] {
        let mut terms = json!({"budget_msat":100000,"per_call_max_msat":10000,"window_secs":600});
        terms[extra] = json!(true);
        assert_ne!(
            f.call(
                false,
                true,
                "POST",
                "/api/v1/pair/approval-request",
                json!({"kind":"spend_grant","terms":terms})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
}
#[tokio::test]
async fn restart_drops_pending_and_retains_signed_spend_receipt() {
    let f = Fixture::new(true);
    let first = f.request(false).await;
    assert_eq!(
        f.approve(
            &first,
            f.sign(first["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let pending = f.request(false).await;
    let root = konsensus_core::OwnerApprovalKey::from_mnemonic(MNEMONIC, "", &[9; 32]).unwrap();
    let reopened = PairingService::open(f.dir.path(), f.svc.bound_fingerprint(), false)
        .unwrap()
        .with_local_owner_device()
        .with_owner_approval_key(root.verifying_key());
    assert!(reopened
        .owner_approval_status(
            &f.requester.client_id,
            f.requester.epoch,
            pending["op_id"].as_str().unwrap()
        )
        .is_err());
    assert!(reopened.grant_view_for(&f.requester.client_id).is_some());
    assert!(reopened
        .take_first_contact(&f.requester.client_id, f.requester.epoch, PEER)
        .is_none());
}
#[tokio::test]
async fn approver_rate_limit_returns_429_and_never_grants() {
    let f = Fixture::new(true);
    let op = f.request(false).await;
    for _ in 0..30 {
        assert_eq!(
            f.approve(&op, "00".into(), true, true).await.0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        f.approve(
            &op,
            f.sign(op["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
}

#[tokio::test]
async fn home_device_first_contact_is_visible_to_existing_status_polling() {
    let f = Fixture::new(true);
    let spend = f.request(false).await;
    assert_eq!(
        f.approve(
            &spend,
            f.sign(spend["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, op) = f
        .call(
            false,
            true,
            "POST",
            "/api/v1/pair/approval-request",
            json!({"kind":"first_contact","terms":{"recipient":PEER,"max_total_msat":1000}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        f.approve(
            &op,
            f.sign(op["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let path = format!(
        "/api/v1/pair/first-contact-grant/{}?recipient={PEER}",
        spend["op_id"].as_str().unwrap()
    );
    let (status, body) = f.call(false, true, "GET", &path, json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "approved");
    assert_eq!(body["approval"]["max_total_msat"], 1000);
    assert_eq!(
        body["approval"]["granted_by"],
        format!("device:{}", f.key_id)
    );
    assert!(
        body["approval"]["expires_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp() + 120
    );
}

#[tokio::test]
async fn owner_token_on_another_pairings_noise_session_is_refused() {
    let mut f = Fixture::new(true);
    let op = f.request(false).await;
    let signature = f.sign(op["approval_message"].as_str().unwrap());
    // Real token for owner; server-supplied Noise context for requester.
    f.token = f.owner_token.clone();
    assert_eq!(
        f.approve(&op, signature, false, true).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
}

#[tokio::test(start_paused = true)]
async fn device_approved_first_contact_compose_pays_and_consumes_once() {
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_lightning::shared_mock::SharedMockProvider;
    let mut f = Fixture::new(true);
    let path = f.dir.path().join("lightning.db");
    let sender = Arc::new(SharedMockProvider::new(&path, "sender", 100_000).unwrap());
    let receiver = Arc::new(SharedMockProvider::new(&path, "receiver", 0).unwrap());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let target = receiver.clone();
    let transport = ConnectedStubTransport::new(vec![peer], f.state.invoice_requests.clone())
        .with_invoice_responder(move |request_id, _hint| {
            let invoice = futures::executor::block_on(target.create_invoice(
                2000,
                &format!("konsensus:{request_id}:message=2000"),
                55,
            ))
            .unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                recipient: peer,
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            })
        });
    f.state = Arc::new(AppState {
        lightning: sender.clone(),
        transport: Arc::new(transport),
        ..(*f.state).clone()
    });
    let sessions = f.state.session_manager.clone();
    let handshake = tokio::spawn(async move {
        loop {
            if receiver.get_balance_msat().await.unwrap() > 0 {
                let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
                sessions
                    .initiate_session(&peer, &target.prekey_bundle().await)
                    .await
                    .unwrap();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    });
    let spend = f.request(false).await;
    assert_eq!(
        f.approve(
            &spend,
            f.sign(spend["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let signing = SigningKey::from_bytes(&[81; 32]);
    let challenge = f.svc.issue_token_challenge(&f.requester.client_id).unwrap();
    f.token = f
        .svc
        .issue_token(
            &f.state.identity.node_id().to_hex(),
            &f.state.jwt_secret,
            &f.requester.client_id,
            &challenge,
            &hex::encode(signing.sign(challenge.as_bytes()).to_bytes()),
        )
        .unwrap()
        .token;
    let send = json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"hello stranger","max_total_msat":4000,"max_routing_fee_msat":0});
    let (status, body) = f
        .call(
            false,
            true,
            "POST",
            "/api/v1/messages/compose",
            send.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000);
    let (status,op)=f.call(false,true,"POST","/api/v1/pair/approval-request",json!({"kind":"first_contact","terms":{"recipient":peer.to_hex(),"max_total_msat":4000}})).await;
    assert_eq!(status, StatusCode::OK, "{op}");
    assert_eq!(
        f.approve(
            &op,
            f.sign(op["approval_message"].as_str().unwrap()),
            true,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, body) = f
        .call(false, true, "POST", "/api/v1/messages/compose", send)
        .await;
    handshake.abort();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 4000);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 96000);
    assert_eq!(
        f.svc
            .grant_view_for(&f.requester.client_id)
            .unwrap()
            .used_msat,
        4000
    );
    assert!(f
        .svc
        .take_first_contact(&f.requester.client_id, f.requester.epoch, &peer.to_hex())
        .is_none());
    let (status, body) = f
        .call(
            false,
            true,
            "GET",
            &format!(
                "/api/v1/pair/first-contact-grant/{}?recipient={}",
                spend["op_id"].as_str().unwrap(),
                peer.to_hex()
            ),
            json!(null),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "consumed");
}

#[tokio::test]
async fn status_advertises_capability_and_console_cannot_approve_device_operations() {
    let f = Fixture::new(true);
    let (status, body) = f
        .call(false, true, "GET", "/api/v1/status", json!(null))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["api_capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("owner_device_approval_v1")));
    let op = f.request(false).await;
    let response=test_router(f.state.clone()).oneshot(Request::builder().method("POST")
        .uri(format!("/api/v1/pair/approval/{}/approve",op["op_id"].as_str().unwrap()))
        .header("content-type","application/json").header("authorization",format!("Bearer {}",f.owner_token))
        .body(Body::from(json!({"approver_key_id":f.key_id,"signature":f.sign(op["approval_message"].as_str().unwrap())}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
}

#[tokio::test]
async fn read_only_paired_token_can_request_but_cannot_approve() {
    use konsensus_api::auth::{create_paired_token, Scope};
    let mut f = Fixture::new(true);
    f.token = create_paired_token(
        &f.state.identity.node_id().to_hex(),
        &f.state.jwt_secret,
        vec![Scope::Read],
        &f.requester.client_id,
        f.requester.epoch,
        &f.svc.bound_fingerprint(),
    )
    .unwrap();
    let op = f.request(false).await;
    assert_eq!(
        f.approve(
            &op,
            f.sign(op["approval_message"].as_str().unwrap()),
            false,
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(f.svc.grant_view_for(&f.requester.client_id).is_none());
}
