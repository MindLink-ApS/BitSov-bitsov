//! G1: budget-scoped, short-lived spend grants.
//!
//! Every paid path a paired client can reach is driven over the real router
//! with a paired token, and every assertion checks the **effect** — how many
//! payments the Lightning provider saw, and what the durable ledger says —
//! not only the status code. Each refusal has a positive control beside it, so
//! the suite cannot pass by refusing everything.
//!
//! No live node, wallet or data directory: temp directories, a counting
//! Lightning double, and loopback-free `oneshot` requests.

#![allow(dead_code)]

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::auth::Scope;
use konsensus_api::control::{self, ControlContext, ControlRequest, ControlResponse};
use konsensus_api::pairing::{self, PairingService};
use konsensus_api::spend_budget::{BudgetRefusal, Charge, GrantTerms};
use konsensus_api::state::AppState;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::types::NodeId;

use common::*;

/// The peer's Lightning pubkey, as the compose path keysends to it.
const PEER_LN: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_LN: &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ─── A Lightning double with selectable outcomes ───────────────────

const SETTLE: u8 = 0;
const UNKNOWN: u8 = 1;
const NOT_DISPATCHED: u8 = 2;
const FAILED: u8 = 3;

/// Counts every money-moving call and settles, loses, refuses or fails it.
#[derive(Default)]
struct Wallet {
    outgoing: std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    liquidity: std::sync::Mutex<Option<Arc<konsensus_lightning::liquidity::LiquidityClient>>>,
    mode: AtomicU8,
    pause_dispatch: AtomicBool,
    waiting: AtomicUsize,
    resume: tokio::sync::Notify,
    money: AtomicUsize,
    invoices: AtomicUsize,
    /// Principal that actually left (settled or unknown after dispatch).
    left_msat: AtomicU64,
}

impl Wallet {
    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
    fn money(&self) -> usize {
        self.money.load(Ordering::SeqCst)
    }
    fn left(&self) -> u64 {
        self.left_msat.load(Ordering::SeqCst)
    }
    async fn outcome(&self, amount_msat: u64) -> Result<PaymentDetails, LightningError> {
        if self.pause_dispatch.load(Ordering::SeqCst) {
            self.waiting.fetch_add(1, Ordering::SeqCst);
            self.resume.notified().await;
        }
        self.money.fetch_add(1, Ordering::SeqCst);
        // Yield so concurrent requests genuinely interleave around the debit.
        tokio::task::yield_now().await;
        let status = match self.mode.load(Ordering::SeqCst) {
            NOT_DISPATCHED => {
                return Err(LightningError::PaymentNotDispatched(
                    "local validation".into(),
                ))
            }
            UNKNOWN => {
                self.left_msat.fetch_add(amount_msat, Ordering::SeqCst);
                return Err(LightningError::Connection(
                    "response lost after dispatch".into(),
                ));
            }
            FAILED => PaymentStatus::Failed,
            _ => {
                self.left_msat.fetch_add(amount_msat, Ordering::SeqCst);
                PaymentStatus::Settled
            }
        };
        Ok(PaymentDetails {
            payment_hash: "ab".repeat(32),
            preimage: (status == PaymentStatus::Settled).then(|| "cd".repeat(32)),
            amount_msat,
            status,
            direction: PaymentDirection::Outgoing,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: None,
        })
    }
}

#[async_trait]
impl LightningProvider for Wallet {
    async fn quote_liquidity(&self, owner: &str, gross: u64, cap: u64) -> Result<konsensus_core::traits::liquidity::LiquidityQuote, LightningError> {
        let client = self.liquidity.lock().unwrap().clone().unwrap();
        client.quote(owner, gross, cap).await
    }
    fn liquidity_quote(&self, owner: &str, id: &str) -> Result<konsensus_core::traits::liquidity::LiquidityQuote, LightningError> {
        self.liquidity.lock().unwrap().as_ref().unwrap().terms(owner, id)
    }
    async fn accept_liquidity(&self, owner: &str, id: &str) -> Result<Invoice, LightningError> {
        self.liquidity.lock().unwrap().as_ref().unwrap().accept(owner, id)
    }
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.invoices.fetch_add(1, Ordering::SeqCst);
        StubLightning
            .create_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn pay_invoice_with_fee_limit(&self, bolt11: &str, _max_fee_msat: u64) -> Result<PaymentDetails, LightningError> {
        let invoice = bolt11.parse::<lightning_invoice::Bolt11Invoice>().unwrap();
        let mut paid = self.pay_invoice(bolt11).await?;
        paid.payment_hash = invoice.payment_hash().to_string();
        paid.fee_msat = Some(0);
        Ok(paid)
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let amount = bolt11
            .parse::<lightning_invoice::Bolt11Invoice>()
            .ok()
            .and_then(|i| i.amount_milli_satoshis())
            .unwrap_or(0);
        let invoice = bolt11.parse::<lightning_invoice::Bolt11Invoice>().ok();
        if let Some(invoice) = &invoice {
            self.outgoing.lock().unwrap().insert(invoice.payment_hash().to_string(), amount);
        }
        self.outcome(amount).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        let amount = self.outgoing.lock().unwrap().get(hash).copied();
        if let Some(amount_msat) = amount {
            return Ok(PaymentDetails {
                payment_hash: hash.into(), preimage: None, amount_msat,
                status: match self.mode.load(Ordering::SeqCst) {
                    FAILED => PaymentStatus::Failed,
                    UNKNOWN => PaymentStatus::InFlight,
                    _ => PaymentStatus::Settled,
                },
                direction: PaymentDirection::Outgoing, timestamp: 1_700_000_000,
                memo: None, fee_msat: Some(0),
            });
        }
        StubLightning.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        StubLightning.get_balance_msat().await
    }
    async fn keysend(
        &self,
        _dest: &str,
        amount_msat: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        self.outcome(amount_msat).await
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn send_onchain(
        &self,
        _address: &str,
        _amount_sats: u64,
        _fee: Option<f32>,
    ) -> Result<String, LightningError> {
        self.money.fetch_add(1, Ordering::SeqCst);
        Ok("deadbeef".repeat(8))
    }
    async fn open_channel(
        &self,
        _peer: &str,
        _addr: &str,
        _amount_sats: u64,
        _announce: bool,
        _fee: Option<f32>,
    ) -> Result<String, LightningError> {
        self.money.fetch_add(1, Ordering::SeqCst);
        Ok("chan".into())
    }
}

// ─── Fixture: an owner-run node with one paired app ────────────────

struct Fx {
    state: Arc<AppState>,
    service: Arc<PairingService>,
    console: OwnerConsole,
    key: SigningKey,
    client_id: String,
    peer: NodeId,
    wallet: Arc<Wallet>,
    tmp: tempfile::TempDir,
}

fn open_owner_service(
    dir: &std::path::Path,
    fingerprint: &str,
    console: &OwnerConsole,
) -> Arc<PairingService> {
    Arc::new(
        PairingService::open(dir, fingerprint.to_string(), true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    )
}

async fn fixture() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let wallet = Arc::new(Wallet::default());
    let base = test_state_with_lightning(wallet.clone());
    let peer = setup_e2ee_session(&base.session_manager).await;
    let fingerprint = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let console = OwnerConsole::default();
    let service = open_owner_service(tmp.path(), &fingerprint, &console);
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        transport: Arc::new(ConnectedStubTransport::new(
            vec![peer],
            base.invoice_requests.clone(),
        )),
        data_dir: Some(tmp.path().to_path_buf()),
        ..(*base).clone()
    });
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, PEER_LN.into());

    let key = SigningKey::from_bytes(&[7u8; 32]);
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
        peer,
        wallet,
        tmp,
    }
}

impl Fx {
    /// Reopen the same data directory as a restarted node would.
    fn restart(&mut self) {
        let fingerprint = self.service.bound_fingerprint();
        self.service = open_owner_service(self.tmp.path(), &fingerprint, &self.console);
        self.state = Arc::new(AppState {
            pairing: Some(Arc::clone(&self.service)),
            ..(*self.state).clone()
        });
    }

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

    async fn owner_confirm(&self, recipient: &str, max_total_msat: u64) -> (StatusCode, Value) {
        let owner = konsensus_api::auth::create_token(&self.state.identity.node_id().to_hex(), &self.state.jwt_secret, Scope::all()).unwrap();
        let op_id = self.service.grant_view_for(&self.client_id).map(|g| g.op_id).unwrap_or_default();
        self.call("POST", "/api/v1/pair/first-contact-grant", Some(json!({
            "client_id": self.client_id, "grant_op_id": op_id,
            "recipient": recipient, "max_total_msat": max_total_msat,
        })), Some(&owner)).await
    }

    /// A paired token, freshly issued (so it carries whatever grant is live).
    async fn token(&self) -> String {
        let challenge = self.service.issue_token_challenge(&self.client_id).unwrap();
        let sig = hex::encode(self.key.sign(challenge.as_bytes()).to_bytes());
        let (status, body) = self
            .call(
                "POST",
                "/api/v1/pair/token",
                Some(
                    json!({"client_id": self.client_id, "challenge": challenge, "signature": sig}),
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["token"].as_str().unwrap().to_string()
    }

    /// The app asks (optionally proposing a budget); the owner grants `terms`
    /// at the control socket with the console code. Returns a new token.
    async fn grant(&self, proposal: Option<Value>, terms: GrantTerms) -> String {
        let read = self.token().await;
        let mut body = json!({"scopes": ["spend"]});
        if let Some(p) = proposal {
            body["budget"] = p;
        }
        let (status, op) = self
            .call(
                "POST",
                "/api/v1/pair/elevation-request",
                Some(body),
                Some(&read),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{op}");
        let op_id = op["op_id"].as_str().unwrap().to_string();
        let pending = self
            .service
            .snapshot()
            .pending_elevations
            .into_iter()
            .find(|e| e.op_id == op_id)
            .unwrap();
        let phrase = self
            .console
            .confirmation(&pairing::grant_confirmation_phrase(&pending));
        let resp = control::handle(
            &self.control(),
            ControlRequest::Grant {
                op_id,
                confirmation: phrase,
                terms,
            },
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }), "{resp:?}");
        self.token().await
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        call(&self.state, method, uri, body, token).await
    }

    fn used(&self) -> u64 {
        self.service
            .reload_from_disk()
            .unwrap()
            .grants
            .first()
            .and_then(|g| g.budget.as_ref())
            .map(|b| b.used_msat)
            .unwrap_or(0)
    }

    async fn compose(&self, token: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/api/v1/messages/compose",
            Some(json!({"recipient": self.peer.to_hex(), "kind": 100, "plaintext": "hi"})),
            Some(token),
        )
        .await
    }

    async fn keysend(&self, token: &str, dest: &str, amount_msat: u64) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/api/v1/payments/keysend",
            Some(json!({"dest_pubkey": dest, "amount_msat": amount_msat})),
            Some(token),
        )
        .await
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
    let resp = test_router(state.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)}));
    (status, json)
}

fn assert_budget_exceeded(status: StatusCode, body: &Value, reason: &str) {
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded", "{body}");
    assert_eq!(body["reason"], reason, "{body}");
}

fn amountless_bolt11() -> String {
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder};
    InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("no amount".into())
        .payment_hash(sha256::Hash::from_slice(&[0u8; 32]).unwrap())
        .payment_secret(lightning_invoice::PaymentSecret([42u8; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(18)
        .build_signed(|hash| {
            let secp = secp256k1::Secp256k1::new();
            let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
            secp.sign_ecdsa_recoverable(hash, &key)
        })
        .unwrap()
        .to_string()
}

fn payee_of(bolt11: &str) -> String {
    let inv = bolt11.parse::<lightning_invoice::Bolt11Invoice>().unwrap();
    hex::encode(inv.recover_payee_pub_key().serialize())
}

// ─── Grant, advertise, owner terms ─────────────────────────────────

#[tokio::test]
async fn status_advertises_the_budget_grant_capability() {
    let fx = fixture().await;
    let (status, body) = fx
        .call(
            "GET",
            "/api/v1/status",
            None,
            Some(auth_header(&fx.state).trim_start_matches("Bearer ")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let caps = body["api_capabilities"].as_array().unwrap();
    assert!(caps.contains(&json!("spend_budget_grant_v1")), "{caps:?}");
    assert!(
        caps.contains(&json!("paid_send_caps_v1")),
        "#80 capability kept"
    );
}

#[tokio::test]
async fn owner_terms_win_over_the_proposal_and_the_window_is_capped_at_24h() {
    let fx = fixture().await;
    let read = fx.token().await;

    // A proposal beyond 24 h is refused at request time: nothing pending.
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/pair/elevation-request",
            Some(json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000_000, "ttl_secs": 90_000}})),
            Some(&read),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(fx.service.snapshot().pending_elevations.is_empty());

    // The proposal is shown to the owner through Describe…
    let (status, op) = fx
        .call(
            "POST",
            "/api/v1/pair/elevation-request",
            Some(json!({"scopes": ["spend"], "budget": {"budget_msat": 2_000_000}})),
            Some(&read),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{op}");
    let op_id = op["op_id"].as_str().unwrap().to_string();
    let described = control::handle(
        &fx.control(),
        ControlRequest::Describe {
            op_id: op_id.clone(),
        },
    );
    let ControlResponse::Describe {
        summary,
        proposed_terms,
        confirmation_label,
    } = described
    else {
        panic!("{described:?}")
    };
    assert_eq!(proposed_terms.unwrap().budget_msat, 2_000_000);
    assert!(summary.contains("2000 sats"), "{summary}");

    // …an owner window over 24 h writes nothing…
    let phrase = fx.console.confirmation(&confirmation_label);
    let refused = control::handle(
        &fx.control(),
        ControlRequest::Grant {
            op_id: op_id.clone(),
            confirmation: phrase.clone(),
            terms: GrantTerms::new(500_000).for_secs(24 * 3600 + 1),
        },
    );
    assert!(
        matches!(refused, ControlResponse::Error { .. }),
        "{refused:?}"
    );
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());

    // …and the owner's narrower terms are what the node enforces.
    let ok = control::handle(
        &fx.control(),
        ControlRequest::Grant {
            op_id,
            confirmation: phrase,
            terms: GrantTerms::new(500_000).for_secs(3600).per_call(2_000),
        },
    );
    assert!(matches!(ok, ControlResponse::Ok { .. }), "{ok:?}");
    let spend = fx.token().await;
    let (_, view) = fx
        .call("GET", "/api/v1/pair/grant", None, Some(&spend))
        .await;
    let g = &view["grant"];
    assert_eq!(g["budget_msat"], 500_000);
    assert_eq!(g["per_call_max_msat"], 2_000);
    assert_eq!(g["remaining_msat"], 500_000);
    assert_eq!(
        g["expires_at"].as_i64().unwrap() - g["granted_at"].as_i64().unwrap(),
        3600
    );
}

// ─── Every paid path debits before it pays ─────────────────────────

#[tokio::test]
async fn compose_debits_each_message_and_refuses_before_any_invoice_or_payment() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(2_500)).await;

    for n in 1..=2u64 {
        let (status, body) = fx.compose(&token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.used(), n * 1_000);
    }
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "total");
    assert_eq!(body["remaining_msat"], 500);
    assert_eq!(fx.wallet.money(), 2, "the refused message paid nothing");
    assert!(fx.state.invoice_requests.lock().await.is_empty());
    assert_eq!(fx.used(), 2_000, "a refusal reserves nothing");
}

#[tokio::test]
async fn per_call_and_per_recipient_budgets_hold() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000).per_call(999)).await;
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0);

    let token = fx
        .grant(
            None,
            GrantTerms::new(10_000).recipient(&fx.peer.to_hex(), 1_000),
        )
        .await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "recipient");
    assert_eq!(body["remaining_msat"], 0);
    // POSITIVE CONTROL: another recipient is still bounded only by the total.
    let (status, body) = fx.keysend(&token, OTHER_LN, 3_000).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), 2);
    assert_eq!(fx.used(), 4_000);
}

#[tokio::test]
async fn file_send_is_debited_and_refused_when_spent() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(1_500)).await;
    let (status, file) = fx
        .call(
            "POST",
            "/api/v1/files",
            Some(json!({"filename": "hi.txt", "mime_type": "text/plain", "data_b64": "aGk="})),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{file}");
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    let body = json!({"recipient": fx.peer.to_hex()});
    let (status, receipt) = fx
        .call("POST", &path, Some(body.clone()), Some(&token))
        .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(fx.used(), 1_000);
    let path = lifecycle::upload_probe_file(&fx).await;
    let (status, err) = fx.call("POST", &path, Some(body), Some(&token)).await;
    assert_budget_exceeded(status, &err, "total");
    assert_eq!(fx.wallet.money(), 1);
}

#[tokio::test]
async fn pay_debits_the_payee_and_refuses_amountless_invoices() {
    let fx = fixture().await;
    let bolt11 = create_test_bolt11(1_500);
    let payee = payee_of(&bolt11);
    let token = fx
        .grant(None, GrantTerms::new(10_000).recipient(&payee, 2_000))
        .await;

    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/payments/pay",
            Some(json!({"bolt11": amountless_bolt11()})),
            Some(&token),
        )
        .await;
    assert_budget_exceeded(status, &body, "unpriced");
    assert_eq!(fx.wallet.money(), 0);

    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/payments/pay",
            Some(json!({"bolt11": bolt11})),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.used(), 1_500);
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/payments/pay",
            Some(json!({"bolt11": create_test_bolt11(1_500)})),
            Some(&token),
        )
        .await;
    assert_budget_exceeded(status, &body, "recipient");
    assert_eq!(body["remaining_msat"], 500);
    assert_eq!(fx.wallet.money(), 1);
}

#[tokio::test]
async fn keysend_outcomes_settle_release_or_stay_reserved() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;

    assert_eq!(fx.keysend(&token, OTHER_LN, 1_000).await.0, StatusCode::OK);
    assert_eq!(fx.used(), 1_000, "settled: debited");

    fx.wallet.set(NOT_DISPATCHED);
    assert!(!fx.keysend(&token, OTHER_LN, 2_000).await.0.is_success());
    assert_eq!(fx.used(), 1_000, "rejected before dispatch: released");

    fx.wallet.set(FAILED);
    let _ = fx.keysend(&token, OTHER_LN, 2_000).await;
    assert_eq!(fx.used(), 1_000, "confirmed failed: released");

    fx.wallet.set(UNKNOWN);
    assert!(!fx.keysend(&token, OTHER_LN, 3_000).await.0.is_success());
    assert_eq!(fx.used(), 4_000, "unknown: the whole amount stays reserved");
    assert!(
        fx.used() >= fx.wallet.left(),
        "the tally never under-counts"
    );
}

#[tokio::test]
async fn compose_unknown_stays_reserved_and_refusal_before_dispatch_is_released() {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    fx.wallet.set(UNKNOWN);
    let (status, _) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(fx.used(), 1_000, "unknown: the price stays reserved");

    // The recipient went offline: the payment is refused after the debit but
    // before any dispatch, so the reservation is released.
    fx.wallet.set(SETTLE);
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![],
        fx.state.invoice_requests.clone(),
    ));
    fx.state = Arc::new(AppState {
        transport,
        ..(*fx.state).clone()
    });
    let (status, body) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(fx.wallet.money(), 1);
    assert_eq!(fx.used(), 1_000, "refused before dispatch: released");
}

#[tokio::test]
async fn room_fanout_is_one_debited_call_and_refused_members_are_released() {
    let fx = fixture().await;
    let owner = auth_header(&fx.state);
    let owner = owner.trim_start_matches("Bearer ");
    let (_, room) = fx
        .call(
            "POST",
            "/api/v1/rooms",
            Some(json!({"name": "budget"})),
            Some(owner),
        )
        .await;
    let id = room["id"].as_str().unwrap().to_string();
    let other = "bb".repeat(32);
    for member in [fx.peer.to_hex(), other.clone()] {
        let (status, _) = fx
            .call(
                "POST",
                &format!("/api/v1/rooms/{id}/members"),
                Some(json!({"node_id": member})),
                Some(owner),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    let body = json!({"recipient": id, "is_room": true, "kind": 100, "plaintext": "room"});

    // The whole fan-out is one call: 2 × 1000 exceeds a 1999 per-call max,
    // so no member is paid.
    let token = fx
        .grant(None, GrantTerms::new(10_000).per_call(1_999))
        .await;
    let (status, err) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(body.clone()),
            Some(&token),
        )
        .await;
    assert_budget_exceeded(status, &err, "per_call");
    assert_eq!(fx.wallet.money(), 0);

    // POSITIVE CONTROL: within budget, the reachable member settles and the
    // member without a session is refused and released.
    let token = fx
        .grant(None, GrantTerms::new(10_000).per_call(2_000))
        .await;
    let (status, receipt) = fx
        .call("POST", "/api/v1/messages/compose", Some(body), Some(&token))
        .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let rows = receipt["member_outcomes"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|r| r["recipient"] == other && r["status"] == "refused"));
    assert_eq!(fx.wallet.money(), 1);
    assert_eq!(fx.used(), 1_000, "only the settled member stays debited");
}

#[tokio::test]
async fn first_contact_admission_is_not_paid_from_a_budget() {
    let mut fx = fixture().await;
    let stranger = NodeId::from_hex(&"cc".repeat(32)).unwrap();
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![stranger],
        fx.state.invoice_requests.clone(),
    ));
    fx.state = Arc::new(AppState {
        transport,
        ..(*fx.state).clone()
    });
    let token = fx.grant(None, GrantTerms::new(1_000_000)).await;
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(json!({"recipient": stranger.to_hex(), "kind": 100, "plaintext": "hello"})),
            Some(&token),
        )
        .await;
    // #85: without the owner's one-time confirmation, before anything else.
    assert_budget_exceeded(status, &body, "first_contact");
    assert_eq!(fx.wallet.money(), 0);
    assert!(fx.state.invoice_requests.lock().await.is_empty());
}

#[tokio::test]
async fn preencrypted_send_moves_no_value_and_is_not_debited() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/messages",
            Some(
                json!({"recipient": fx.peer.to_hex(), "kind": 100, "ciphertext": "aa",
                "payment_hash": "bb".repeat(32), "preimage": "cc".repeat(32), "amount_msat": 1000}),
            ),
            Some(&token),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "a budget grant reaches the route: {body}"
    );
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn unmetered_money_routes_refuse_a_paired_grant() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(100_000_000)).await;
    for (uri, body) in [
        (
            "/api/v1/payments/send-onchain",
            json!({"address": "bcrt1qx", "amount_sats": 1000}),
        ),
        (
            "/api/v1/payments/open-channel",
            json!({"peer_pubkey": OTHER_LN, "peer_addr": "127.0.0.1:9735", "amount_sats": 20000}),
        ),
    ] {
        let (status, err) = fx.call("POST", uri, Some(body), Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {err}");
    }
    assert_eq!(fx.wallet.money(), 0);
    // POSITIVE CONTROL: the owner's own key is not metered.
    let owner = auth_header(&fx.state);
    let (status, _) = fx
        .call(
            "POST",
            "/api/v1/payments/send-onchain",
            Some(json!({"address": "bcrt1qx", "amount_sats": 1000})),
            Some(owner.trim_start_matches("Bearer ")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fx.used(), 0);
}

// ─── Revoke, rotate, expire, restart ───────────────────────────────

#[tokio::test]
async fn owner_revoke_stops_spend_on_the_next_request() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);

    let resp = control::handle(
        &fx.control(),
        ControlRequest::RevokeGrant {
            client_id: Some(fx.client_id.clone()),
        },
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }), "{resp:?}");
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());

    // The outstanding token claims spend the pairing no longer holds.
    let (status, _) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fx.wallet.money(), 1);
    // The pairing itself survives: a fresh token is read+receive.
    let fresh = fx.token().await;
    let claims = konsensus_api::auth::validate_token(&fresh, &fx.state.jwt_secret).unwrap();
    assert!(!claims.scp.contains(&Scope::Spend));
    let (status, view) = fx
        .call("GET", "/api/v1/pair/grant", None, Some(&fresh))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(view["grant"].is_null());
}

#[tokio::test]
async fn pairing_rotation_and_epoch_bump_revoke_the_grant() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    fx.service.bump_epoch(&fx.client_id).unwrap();
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(fx.compose(&token).await.0, StatusCode::UNAUTHORIZED);

    let _ = fx.grant(None, GrantTerms::new(10_000)).await;
    let new_key = SigningKey::from_bytes(&[9u8; 32]);
    let new_pub = hex::encode(new_key.verifying_key().to_bytes());
    let msg = format!("bitsov-pair-rotate-v1:{}:{new_pub}", fx.client_id);
    let sig = hex::encode(fx.key.sign(msg.as_bytes()).to_bytes());
    fx.service
        .rotate_client_key(&fx.client_id, &new_pub, &sig)
        .unwrap();
    assert!(
        fx.service.reload_from_disk().unwrap().grants.is_empty(),
        "a rotated key does not inherit a spend grant"
    );
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn expiry_stops_spend_and_the_grant_does_not_outlive_it_on_disk() {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000).for_secs(3600)).await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);

    // Age the grant on disk (the durable file is the source of truth), then
    // restart: the expired grant is dropped at open, not merely ignored.
    let path = fx.tmp.path().join("pairing").join("clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    file["grants"][0]["granted_at"] = json!(now - 3601);
    file["grants"][0]["expires_at"] = json!(now - 1);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    fx.restart();

    let on_disk: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["grants"], json!([]), "expired grant left on disk");
    let (status, _) = fx.compose(&token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fx.wallet.money(), 1);

    // A hand-edited expiry past the 24 h cap is not an extension.
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let granted = file["grants"][0]["granted_at"].as_i64().unwrap();
    file["grants"][0]["expires_at"] = json!(granted + 48 * 3600);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    fx.restart();
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(fx.compose(&token).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_grant_is_swept_without_any_other_write() {
    let fx = fixture().await;
    let _ = fx.grant(None, GrantTerms::new(10_000)).await;
    // Age the in-memory and on-disk state together by reopening, then let
    // the sweep run with no other writer.
    let path = fx.tmp.path().join("pairing").join("clients.json");
    assert_eq!(
        fx.service.prune_expired_grants().unwrap(),
        0,
        "a live grant is kept"
    );
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    file["grants"][0]["granted_at"] = json!(now - 100);
    file["grants"][0]["expires_at"] = json!(now + 3);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let service = open_owner_service(fx.tmp.path(), &fx.service.bound_fingerprint(), &fx.console);
    assert_eq!(service.reload_from_disk().unwrap().grants.len(), 1);
    while chrono::Utc::now().timestamp() < now + 3 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(service.prune_expired_grants().unwrap(), 1);
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
}

#[tokio::test]
async fn restart_keeps_the_tally_and_never_extends_the_window() {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(3_000).for_secs(7_200)).await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);
    fx.wallet.set(UNKNOWN);
    assert!(!fx.keysend(&token, OTHER_LN, 1_000).await.0.is_success());
    let before = fx.service.grant_view_for(&fx.client_id).unwrap();
    assert_eq!(before.used_msat, 2_000);

    fx.restart();
    let after = fx.service.grant_view_for(&fx.client_id).unwrap();
    assert_eq!(
        after.used_msat, 2_000,
        "settled and unknown reservations survive"
    );
    assert_eq!(
        after.expires_at, before.expires_at,
        "a restart never extends the grant"
    );

    // The same token keeps working against the remaining 1000 msat only.
    fx.wallet.set(SETTLE);
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "total");
    assert_eq!(fx.used(), 3_000);
    assert_eq!(fx.wallet.money(), 3);
}

#[tokio::test]
async fn a_pre_g1_unmetered_grant_is_never_honoured() {
    let fx = fixture().await;
    let _ = fx.grant(None, GrantTerms::new(10_000)).await;
    // Rewrite the store as a v1 node left it: a 30-day grant with no budget.
    let path = fx.tmp.path().join("pairing").join("clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    file["version"] = json!(1);
    file["grants"][0].as_object_mut().unwrap().remove("budget");
    file["grants"][0]["granted_at"] = json!(now);
    file["grants"][0]["expires_at"] = json!(now + 30 * 24 * 3600);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let service = open_owner_service(fx.tmp.path(), &fx.service.bound_fingerprint(), &fx.console);
    let durable = service.reload_from_disk().unwrap();
    assert!(durable.grants.is_empty());
    assert_eq!(durable.version, pairing::PAIRING_FILE_VERSION);
    let challenge = service.issue_token_challenge(&fx.client_id).unwrap();
    let sig = hex::encode(fx.key.sign(challenge.as_bytes()).to_bytes());
    let issued = service
        .issue_token(
            "node",
            &fx.state.jwt_secret,
            &fx.client_id,
            &challenge,
            &sig,
        )
        .unwrap();
    assert!(!issued.scopes.contains(&Scope::Spend));
}

#[tokio::test]
async fn a_sidecar_never_meters_or_honours_a_grant() {
    let fx = fixture().await;
    let _ = fx.grant(None, GrantTerms::new(10_000)).await;
    let epoch = fx.service.snapshot().clients[0].epoch;
    let sidecar = PairingService::open(fx.tmp.path(), fx.service.bound_fingerprint(), false)
        .unwrap()
        .without_stdout_code();
    let charge = Charge {
        recipient: fx.peer.to_hex(),
        amount_msat: 1_000,
    };
    assert_eq!(
        sidecar.reserve_spend(&fx.client_id, epoch, vec![charge]),
        Err(BudgetRefusal::NoGrant)
    );
    assert!(sidecar.grant_view_for(&fx.client_id).is_none());
}

// ─── Concurrency ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_paid_calls_never_overspend_the_budget() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(5_000)).await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let state = Arc::clone(&fx.state);
        let token = token.clone();
        let peer = fx.peer.to_hex();
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                call(
                    &state,
                    "POST",
                    "/api/v1/payments/keysend",
                    Some(json!({"dest_pubkey": OTHER_LN, "amount_msat": 1000})),
                    Some(&token),
                )
                .await
                .0
            } else {
                call(
                    &state,
                    "POST",
                    "/api/v1/messages/compose",
                    Some(json!({"recipient": peer, "kind": 100, "plaintext": "race"})),
                    Some(&token),
                )
                .await
                .0
            }
        }));
    }
    let mut ok = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::OK => ok += 1,
            StatusCode::CONFLICT => refused += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 5, "exactly the budget's worth of calls succeed");
    assert_eq!(refused, 19);
    assert_eq!(fx.wallet.money(), 5, "no refused call reached the wallet");
    assert_eq!(fx.wallet.left(), 5_000);
    assert_eq!(fx.used(), 5_000);
}

#[test]
fn concurrent_reservations_on_the_ledger_are_atomic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fx = rt.block_on(async {
        let fx = fixture().await;
        let _ = fx.grant(None, GrantTerms::new(10_000)).await;
        fx
    });
    let epoch = fx.service.snapshot().clients[0].epoch;
    let wins = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..64 {
            s.spawn(|| {
                let charge = Charge {
                    recipient: fx.peer.to_hex(),
                    amount_msat: 1_000,
                };
                if fx
                    .service
                    .reserve_spend(&fx.client_id, epoch, vec![charge])
                    .is_ok()
                {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(wins.load(Ordering::SeqCst), 10);
    assert_eq!(fx.used(), 10_000);
}

#[path = "budget_grant/lifecycle.rs"]
mod lifecycle;

#[path = "budget_grant/expiry.rs"]
mod expiry;

#[tokio::test]
async fn membrane_observes_budget_refusals_on_compose_and_file() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000).per_call(999)).await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::CONFLICT);
    let (_, file) = fx
        .call(
            "POST",
            "/api/v1/files",
            Some(json!({"filename":"hi.txt","mime_type":"text/plain","data_b64":"aGk="})),
            Some(&token),
        )
        .await;
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    assert_eq!(
        fx.call(
            "POST",
            &path,
            Some(json!({"recipient":fx.peer.to_hex()})),
            Some(&token)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (events, totals) = fx.state.audit_log.membrane().read(None, 500);
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|e| e.code == konsensus_api::membrane::Code::BudgetExceeded));
    assert_eq!(totals.outbound_refused, 2);
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn membrane_observes_direct_payment_budget_denials_without_invoice_data() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(1000)).await;
    assert_eq!(
        fx.keysend(&token, OTHER_LN, 2000).await.0,
        StatusCode::CONFLICT
    );
    let invoice = amountless_bolt11();
    assert_eq!(
        fx.call(
            "POST",
            "/api/v1/payments/pay",
            Some(json!({"bolt11":invoice})),
            Some(&token)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (events, totals) = fx.state.audit_log.membrane().read(None, 500);
    assert_eq!(totals.outbound_refused, 2);
    assert!(events.iter().all(|e| e.counterparty.is_none()
        && e.kind.is_none()
        && e.code == konsensus_api::membrane::Code::BudgetExceeded));
    assert!(!serde_json::to_string(&events).unwrap().contains(&invoice));
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn liquidity_requires_separate_authority_and_uses_durable_g1_budget() {
    let mut fx = fixture().await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let epoch = fx.service.snapshot().clients.iter().find(|c| c.client_id == fx.client_id).unwrap().epoch;
    let charge = Charge { recipient: PEER_LN.into(), amount_msat: 2_000 };
    assert!(fx.service.reserve_liquidity_fee(&fx.client_id, epoch, vec![charge.clone()]).is_err());
    let mut terms = GrantTerms::new(10_000).recipient(PEER_LN, 3_000);
    terms.allow_liquidity_fees = true;
    fx.grant(None, terms).await;
    fx.service.reserve_liquidity_fee(&fx.client_id, epoch, vec![charge.clone()]).unwrap();
    fx.restart();
    assert!(fx.service.reserve_liquidity_fee(&fx.client_id, epoch, vec![charge]).is_err(), "restart must not reset fee reservation or recipient cap");
}

#[path = "budget_grant/liquidity.rs"]
mod liquidity_tests;
#[tokio::test]
async fn reservation_resolution_is_idempotent_across_restart() {
    let mut fx = fixture().await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let epoch = fx.service.snapshot().clients.iter().find(|c| c.client_id == fx.client_id).unwrap().epoch;
    let charge = Charge { recipient: fx.peer.to_hex(), amount_msat: 4000 };
    let reservation = fx.service.reserve_spend(&fx.client_id, epoch, vec![charge]).unwrap();
    fx.service.resolve_spend(&reservation, &fx.peer.to_hex(), 2000);
    assert_eq!(fx.used(), 2000);
    fx.restart();
    fx.service.resolve_spend(&reservation, &fx.peer.to_hex(), 2000);
    assert_eq!(fx.used(), 2000, "replayed resolution must not subtract twice");
}

#[path = "budget_grant/first_contact.rs"]
mod first_contact;

#[path = "budget_grant/sponsor.rs"]
mod sponsor;
#[path = "budget_grant/first_contact_grant.rs"]
mod first_contact_grant;

#[tokio::test]
async fn zero_charge_resolution_consumes_its_durable_reservation() {
    let fx = fixture().await;
    fx.grant(None, GrantTerms::new(1000)).await;
    let epoch = fx.service.snapshot().clients.iter().find(|c| c.client_id == fx.client_id).unwrap().epoch;
    fx.service.reserve_spend(&fx.client_id, epoch, vec![]).unwrap();
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.is_empty());
    let reservation = fx.service.reserve_spend(&fx.client_id, epoch,
        vec![Charge { recipient: fx.peer.to_hex(), amount_msat: 0 }]).unwrap();
    fx.service.resolve_spend(&reservation, &fx.peer.to_hex(), 0);
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.is_empty());
}
