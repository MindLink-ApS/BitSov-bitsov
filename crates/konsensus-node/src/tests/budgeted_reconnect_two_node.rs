//! Two-node regression for the reconnect bug (UI-E2E run 7): after a paid
//! admission, a reconnect demoted the sender to a stranger and the recipient
//! then dropped its message-invoice requests in silence, so every send timed
//! out after 30 s.
//!
//! Real pieces: two Noise transports over loopback (the recipient in
//! `price_open`), node A's `POST /api/v1/messages/compose` route (with its
//! admission journal on disk), node B's invoice handler with its stateless
//! quote gate and payment gate with promote-on-paid, both N2 membranes, each
//! side's invoice bookkeeping, and F1's shared mock Lightning ledger. The E2EE
//! sessions are set up directly: in the field X3DH runs after the first
//! admission, and both sides keep the session across a reconnect.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt;

use konsensus_api::membrane::Code;
use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::SessionManager;
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::{ControlEvent, NoiseTransport, ReachabilityMode, TransportConfig};

use super::{
    handle_invoice_error_received, handle_invoice_requested_gated, handle_invoice_response,
    InvoiceRequestOutcome,
};

/// The marker node A's compose puts in an admission envelope (not E2EE).
const ADMISSION_MARKER: &[u8] = b"konsensus:admission:v1";

const JWT_SECRET: &str = "reconnect-regression-jwt-secret";

/// A fresh identity per test: the sender's admission ledger and quote cache
/// are process-wide and keyed by the peer, so tests must not share one.
fn identity() -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::generate().unwrap().1)
}

fn price_open_transport(identity: &Arc<NodeIdentity>) -> Arc<NoiseTransport> {
    let config = TransportConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        admission_mode: ReachabilityMode::PriceOpen,
        ..Default::default()
    };
    Arc::new(NoiseTransport::new(Arc::clone(identity), config))
}

fn pricing() -> Arc<dyn konsensus_core::traits::pricing::PricingEngine> {
    pricing_at(2_000)
}

fn pricing_at(chat_msat: u64) -> Arc<dyn konsensus_core::traits::pricing::PricingEngine> {
    Arc::new(konsensus_pricing::StaticPricingEngine::new(
        konsensus_pricing::StaticPricingConfig {
            chat_msat,
            ..Default::default()
        },
    ))
}

async fn storage() -> Arc<dyn konsensus_storage::Storage> {
    Arc::new(konsensus_storage::sqlite::SqliteStorage::in_memory().await.unwrap())
}

fn audit_log(dir: &std::path::Path) -> Arc<konsensus_api::audit::AuditLog> {
    Arc::new(konsensus_api::audit::AuditLog::open(dir.join("audit.log")).unwrap())
}

type InvoiceRequests =
    Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>>;

/// The owner's terminal, captured: grant confirmations are read from it.
#[derive(Clone, Default)]
struct OwnerConsole(Arc<std::sync::Mutex<Vec<u8>>>);

impl OwnerConsole {
    fn confirmation(&self, label: &str) -> String {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .filter(|line| line.starts_with(&format!("{label} CODE ")))
            .next_back()
            .unwrap_or_else(|| panic!("owner console has no confirmation for {label}"))
            .to_owned()
    }
}

impl std::io::Write for OwnerConsole {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A paired app on node A whose owner granted `terms` at the node's terminal.
/// Returns the pairing service, the client id and a paired token carrying the grant.
fn paired_client(
    dir: &std::path::Path,
    node: &NodeIdentity,
    terms: konsensus_api::spend_budget::GrantTerms,
) -> (Arc<konsensus_api::pairing::PairingService>, String, String) {
    use ed25519_dalek::Signer;
    use konsensus_api::pairing::{self, PairingService};

    let console = OwnerConsole::default();
    let fingerprint = pairing::identity_fingerprint(&node.node_id().to_hex());
    let service = Arc::new(
        PairingService::open(dir, fingerprint, true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
    let challenge = std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let proof = key.sign(&PairingService::proof_message(&outcome.pair_id, &pubkey, &challenge));
    let client = service
        .confirm_pairing(&outcome.pair_id, &hex::encode(proof.to_bytes()), pairing::default_pairing_scopes())
        .unwrap();

    let pending = service
        .create_budget_elevation_request(&client.client_id, vec![konsensus_api::auth::Scope::Spend], None)
        .unwrap();
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&pending));
    service.grant_elevation(&pending.op_id, &phrase, terms).unwrap();

    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let signature = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let token = service
        .issue_token(&node.node_id().to_hex(), JWT_SECRET, &client.client_id, &challenge, &signature)
        .unwrap()
        .token;
    (service, client.client_id, token)
}

/// Node A: the sender, driven through its real compose route.
struct Sender {
    router: axum::Router,
    auth: String,
    wallet: Arc<SharedMockProvider>,
    state: Arc<konsensus_api::AppState>,
    pairing: Option<(Arc<konsensus_api::pairing::PairingService>, String)>,
}

async fn start_sender(
    dir: &std::path::Path,
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    sessions: &Arc<SessionManager>,
    wallet: Arc<SharedMockProvider>,
    grant: Option<konsensus_api::spend_budget::GrantTerms>,
    admission_failure: Option<AdmissionFailure>,
) -> Sender {
    let pairing = grant.map(|terms| paired_client(&dir.join("pairing"), identity, terms));
    let invoice_requests: InvoiceRequests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let state = Arc::new(konsensus_api::AppState {
        identity: Arc::clone(identity),
        storage: storage().await,
        lightning: match admission_failure {
            Some(failure) => Arc::new(UnsettledAdmission { wallet: Arc::clone(&wallet), failure, lost_response: std::sync::atomic::AtomicBool::new(false) }),
            None => Arc::clone(&wallet) as Arc<dyn LightningProvider>,
        },
        chain: Arc::new(konsensus_chain::mock::MockChainProvider::new()),
        pricing: pricing(),
        gate: Arc::new(konsensus_core::PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(konsensus_message::PeerRegistry::new())),
        transport: Arc::clone(transport) as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(sessions),
        jwt_secret: JWT_SECRET.into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pairing: pairing.as_ref().map(|(service, _, _)| Arc::clone(service)),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(
            konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default(),
        ),
        audit_log: audit_log(dir),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        // The admission journal lives here, so a stale settled admission is on disk.
        data_dir: Some(dir.to_path_buf()),
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        lightning_backend: "shared_mock".into(),
        chain_backend: "mock".into(),
        introduction: Default::default(),
        front_door: Default::default(),
        sponsor: Default::default(),
        stun_port: None,
        gossip_validator: None,
        file_staging: Default::default(),
    });

    // A's control plane: the invoice replies it is waiting for.
    let control = Arc::clone(transport);
    tokio::spawn(async move {
        while let Some(event) = control.recv_control().await {
            match event {
                ControlEvent::InvoiceResponseReceived { peer_id, request_id, bolt11, payment_hash } => {
                    handle_invoice_response(&peer_id, &request_id, bolt11, payment_hash, &invoice_requests)
                        .await;
                }
                ControlEvent::InvoiceErrorReceived { peer_id, request_id, reason, privileged } => {
                    handle_invoice_error_received(&peer_id, &request_id, &reason, privileged, &invoice_requests)
                        .await;
                }
                _ => {}
            }
        }
    });

    let auth = match &pairing {
        Some((_, _, token)) => format!("Bearer {token}"),
        None => {
            let token = konsensus_api::auth::create_token(
                &identity.node_id().to_hex(),
                &state.jwt_secret,
                konsensus_api::auth::Scope::all(),
            )
            .unwrap();
            format!("Bearer {token}")
        }
    };
    let router = konsensus_api::build_router(Arc::clone(&state))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    Sender {
        router,
        auth,
        wallet,
        state,
        pairing: pairing.map(|(service, client_id, _)| (service, client_id)),
    }
}

impl Sender {
    async fn post(&self, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", &self.auth)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    async fn owner_confirm(&self, mut body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let (_, client_id) = self.pairing.as_ref().unwrap();
        body["client_id"] = serde_json::json!(client_id);
        body["grant_op_id"] = serde_json::json!(self.grant().op_id);
        let owner = konsensus_api::auth::create_token(&self.state.identity.node_id().to_hex(), &self.state.jwt_secret, konsensus_api::auth::Scope::all()).unwrap();
        let response = self.router.clone().oneshot(Request::builder().method("POST")
            .uri("/api/v1/pair/first-contact-grant").header("authorization", format!("Bearer {owner}"))
            .header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// These reconnect scenarios authorize admission from G1 without a separate
    /// total cap. A capped call may re-admit only when a fresh signed quote fits.
    async fn compose(&self, recipient: &NodeId, text: &str) -> (StatusCode, serde_json::Value) {
        let body = serde_json::json!({
            "recipient": recipient.to_hex(),
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": text,
            "max_routing_fee_msat": 0,
        });
        self.post("/api/v1/messages/compose", body).await
    }

    /// Owner-approved all-in retry: message + re-admission must fit `max_total_msat`.
    async fn compose_capped(
        &self, recipient: &NodeId, text: &str, max_total_msat: u64,
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_json::json!({
            "recipient": recipient.to_hex(),
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": text,
            "max_total_msat": max_total_msat,
            "max_routing_fee_msat": 0,
        });
        self.post("/api/v1/messages/compose", body).await
    }

    /// The paired app's live budget grant, as the node meters it.
    fn grant(&self) -> konsensus_api::spend_budget::GrantView {
        let (service, client_id) = self.pairing.as_ref().expect("a paired sender");
        service.grant_view_for(client_id).expect("a live grant")
    }

    /// A's own N2 events with `code`.
    fn membrane(&self, code: Code) -> Vec<Arc<konsensus_api::membrane::MembraneEvent>> {
        let (events, _) = self.state.audit_log.membrane().read(None, 100);
        events.into_iter().filter(|e| e.code == code).collect()
    }

    /// Each payment A has made, msat.
    async fn paid_out(&self) -> Vec<u64> {
        self.wallet
            .list_payments(100)
            .await
            .unwrap()
            .into_iter()
            .filter(|p| p.direction == PaymentDirection::Outgoing)
            .map(|p| p.amount_msat)
            .collect()
    }
}

/// Node B: the `price_open` recipient. Returns its membrane and the plaintexts
/// it delivers, in order.
#[allow(clippy::too_many_arguments)]
async fn start_recipient(
    dir: &std::path::Path,
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    sessions: &Arc<SessionManager>,
    wallet: Arc<SharedMockProvider>,
    recipient_msat: u64,
    refuse_message: Arc<std::sync::atomic::AtomicBool>,
    refuse_admission_quote: Arc<std::sync::atomic::AtomicBool>,
) -> (Arc<konsensus_api::audit::AuditLog>, mpsc::UnboundedReceiver<String>) {
    let audit = audit_log(dir);
    let lightning: Arc<dyn LightningProvider> = wallet;
    let pricing = pricing_at(recipient_msat);

    // B's control plane: invoice requests, through the real privilege and quote gates.
    {
        let transport = Arc::clone(transport);
        let audit = Arc::clone(&audit);
        let lightning = Arc::clone(&lightning);
        let pricing = Arc::clone(&pricing);
        let us = *identity.node_id();
        tokio::spawn(async move {
            let mut quotes = crate::admission_quotes::AdmissionQuotes::default();
            let mut last_refusal = crate::invoice_refusals::RefusalLimits::default();
            while let Some(event) = transport.recv_control().await {
                if let ControlEvent::InvoiceRequested { source_ip, peer_id, request_id, amount_msat, purpose, privileged } = event {
                    if purpose.starts_with("konsensus:admission")
                        && refuse_admission_quote.load(std::sync::atomic::Ordering::Acquire)
                    {
                        super::send_invoice_refusal(&transport, &peer_id, &request_id, "test:no_admission_quote").await;
                        continue;
                    }
                    if privileged && purpose == "konsensus message"
                        && refuse_message.load(std::sync::atomic::Ordering::Acquire)
                    {
                        super::send_invoice_refusal(&transport, &peer_id, &request_id, "test:message_invoice_refused").await;
                        continue;
                    }
                    handle_invoice_requested_gated(
                        &peer_id, &request_id, amount_msat, &purpose, privileged,
                        &pricing, &lightning, &transport, &us, source_ip, &mut quotes,
                        audit.membrane(), &mut last_refusal,
                    )
                    .await;
                }
            }
        });
    }

    // B's message plane: the payment gate, promote-on-paid, then decrypt.
    let (delivered_tx, delivered_rx) = mpsc::unbounded_channel();
    {
        let transport = Arc::clone(transport);
        let identity = Arc::clone(identity);
        let sessions = Arc::clone(sessions);
        let audit = Arc::clone(&audit);
        let storage = storage().await;
        let nonces = konsensus_storage::StorageNonceAdapter::new(Arc::clone(&storage));
        let registry = tokio::sync::RwLock::new(konsensus_message::PeerRegistry::new());
        let gate = konsensus_core::PaymentGate::new();
        tokio::spawn(async move {
            while let Ok(envelope) = transport.recv().await {
                let verdict = crate::msg_handler::whitelist_then_verify(
                    &envelope,
                    audit.membrane(),
                    &registry,
                    &gate,
                    &nonces,
                    pricing.as_ref(),
                    Some(lightning.as_ref()),
                    0.0,
                    Some(identity.node_id()),
                    ReachabilityMode::PriceOpen,
                    true,
                )
                .await;
                if verdict.is_err() {
                    continue;
                }
                transport.promote_to_privileged(&envelope.sender).await;
                if envelope.ciphertext == ADMISSION_MARKER {
                    continue;
                }
                let message = konsensus_crypto::ratchet_message_from_bytes(&envelope.ciphertext).unwrap();
                let plaintext = sessions.decrypt(&envelope.sender, &message).await.unwrap();
                let _ = delivered_tx.send(String::from_utf8(plaintext).unwrap());
            }
        });
    }
    (audit, delivered_rx)
}

async fn wait_until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting until {what}");
}

async fn privileged_on(transport: &NoiseTransport, peer: &NodeId) -> bool {
    transport.connected_privileged_peers().await.contains(peer)
}

/// Two nodes: A (`grant`: a paired app with that budget grant, else the
/// owner's key) and a `price_open` B, holding an E2EE session, not connected.
struct TwoNodes {
    transport_a: Arc<NoiseTransport>,
    transport_b: Arc<NoiseTransport>,
    alice_id: NodeId,
    bob_id: NodeId,
    addr_b: String,
    sender: Sender,
    refuse_message: Arc<std::sync::atomic::AtomicBool>,
    refuse_admission_quote: Arc<std::sync::atomic::AtomicBool>,
    audit_b: Arc<konsensus_api::audit::AuditLog>,
    delivered: mpsc::UnboundedReceiver<String>,
    _dirs: (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
}

/// `grant` gets B's id, to budget it (or not) in the paired app's grant.
async fn two_nodes(
    grant: impl FnOnce(&NodeId) -> Option<konsensus_api::spend_budget::GrantTerms>,
) -> TwoNodes {
    two_nodes_with_price(grant, 2_000).await
}

async fn two_nodes_with_price(
    grant: impl FnOnce(&NodeId) -> Option<konsensus_api::spend_budget::GrantTerms>,
    recipient_msat: u64,
) -> TwoNodes {
    two_nodes_with_outcome(grant, recipient_msat, None).await
}

async fn two_nodes_with_outcome(
    grant: impl FnOnce(&NodeId) -> Option<konsensus_api::spend_budget::GrantTerms>,
    recipient_msat: u64,
    admission_failure: Option<AdmissionFailure>,
) -> TwoNodes {
    let (alice, bob) = (identity(), identity());
    let grant = grant(bob.node_id());
    let (alice_id, bob_id) = (*alice.node_id(), *bob.node_id());
    let (dir_a, dir_b, ledger) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );

    let transport_a = price_open_transport(&alice);
    let transport_b = price_open_transport(&bob);
    transport_a.start_listener().await.unwrap();
    transport_b.start_listener().await.unwrap();
    let addr_b = transport_b.listen_addr().unwrap().to_string();

    // The E2EE session both sides hold after a first admission.
    let sessions_a = Arc::new(SessionManager::new(Arc::clone(&alice)));
    let sessions_b = Arc::new(SessionManager::new(Arc::clone(&bob)));
    let init = sessions_a
        .initiate_session(&bob_id, &sessions_b.prekey_bundle().await)
        .await
        .unwrap();
    sessions_b.accept_session(&alice_id, &init).await.unwrap();

    let ledger_path = ledger.path().join("ledger.db");
    let wallet_a = Arc::new(SharedMockProvider::new(&ledger_path, "a", 1_000_000).unwrap());
    let wallet_b = Arc::new(SharedMockProvider::new(&ledger_path, "b", 0).unwrap());
    let sender = start_sender(dir_a.path(), &alice, &transport_a, &sessions_a, wallet_a, grant, admission_failure).await;
    let refuse_message = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refuse_admission_quote = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (audit_b, delivered) = start_recipient(
        dir_b.path(), &bob, &transport_b, &sessions_b, wallet_b, recipient_msat,
        Arc::clone(&refuse_message), Arc::clone(&refuse_admission_quote),
    ).await;
    // B issues no quote in its first second after startup (F1 restart quarantine).
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    TwoNodes {
        transport_a,
        transport_b,
        alice_id,
        bob_id,
        addr_b,
        sender,
        refuse_message,
        refuse_admission_quote,
        audit_b,
        delivered,
        _dirs: (dir_a, dir_b, ledger),
    }
}

impl TwoNodes {
    async fn connect(&self) {
        self.transport_a.connect(&self.bob_id, &self.addr_b).await.unwrap();
        wait_until("B sees A", || self.transport_b.is_connected(&self.alice_id)).await;
        assert!(!privileged_on(&self.transport_b, &self.alice_id).await, "a new connection starts unpaid");
    }

    /// B drops the connection and A dials again: B holds A as unpaid again
    /// (doctrine: no durable admission object).
    async fn drop_and_reconnect(&self) {
        self.transport_b.disconnect(&self.alice_id).await.unwrap();
        wait_until("A sees the drop", || async { !self.transport_a.is_connected(&self.bob_id).await }).await;
        self.connect().await;
    }

    async fn send_delivered(&mut self, text: &str) -> serde_json::Value {
        let (status, body) = self.sender.compose(&self.bob_id, text).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delivered"], true, "{body}");
        assert_eq!(self.delivered.recv().await.as_deref(), Some(text));
        assert!(privileged_on(&self.transport_b, &self.alice_id).await, "admission promoted A's connection");
        body
    }

    async fn send_delivered_capped(&mut self, text: &str, max_total_msat: u64) -> serde_json::Value {
        let (status, body) = self.sender.compose_capped(&self.bob_id, text, max_total_msat).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delivered"], true, "{body}");
        assert_eq!(self.delivered.recv().await.as_deref(), Some(text));
        assert!(privileged_on(&self.transport_b, &self.alice_id).await, "admission promoted A's connection");
        body
    }

    fn b_codes(&self) -> Vec<Code> {
        self.audit_b.membrane().read(None, 100).0.iter().map(|e| e.code).collect()
    }

    fn shutdown(&self) {
        self.transport_a.shutdown();
        self.transport_b.shutdown();
    }
}

// ── The regressions ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_message_after_reconnect_is_delivered_not_silently_dropped() {
    let mut net = two_nodes(|_| None).await;

    // 1. Admit: A connects as a stranger; its first paid message pays admission.
    net.connect().await;
    net.send_delivered("before the drop").await;

    // 2. Drop, 3. reconnect, 4. the next paid message is delivered on the
    //    same E2EE session, with no 30 s silent timeout (B's quote window is
    //    waited out once, out loud).
    net.drop_and_reconnect().await;
    let started = std::time::Instant::now();
    net.send_delivered("after the reconnect").await;
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the refusals are answered at once, not by a 30 s timeout ({:?})",
        started.elapsed()
    );

    // Each act re-proven: two admissions and two messages, nothing paid twice.
    assert_eq!(net.sender.paid_out().await.len(), 4, "admission + message, twice");

    // B refused out loud (N2) and never saw a replayed admission proof.
    let codes = net.b_codes();
    assert!(!codes.contains(&Code::AdmissionRequired), "unpaid refusals are aggregate only");
    assert!(net.audit_b.membrane().pre_payment_refusals().buckets.iter().any(|b| b.counts.get(&konsensus_api::membrane::PrePaymentReason::AdmissionRequired).copied().unwrap_or(0) > 0));
    assert!(!codes.contains(&Code::ProofReused), "stale admission proof re-sent: {codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == Code::Settled).count(), 4, "{codes:?}");
    net.shutdown();
}

// ── Budgeted re-admission (CoS decision, 2026-09-27) ────────────────────

/// A day's budget for the paired app; `contact_cap` budgets B in it.
fn budget(bob: &NodeId, contact_cap: Option<u64>) -> konsensus_api::spend_budget::GrantTerms {
    let terms = konsensus_api::spend_budget::GrantTerms::new(200_000)
        .per_call(20_000)
        .for_secs(3_600);
    match contact_cap {
        Some(cap) => terms.recipient(&bob.to_hex(), cap),
        None => terms,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budgeted_contact_is_readmitted_from_the_budget_without_a_prompt() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;

    // Admit, drop, reconnect: each paid send is one call from the paired app.
    // No first-contact grant, no owner step: B is a contact the owner budgeted.
    net.connect().await;
    net.send_delivered("before the drop").await;
    net.drop_and_reconnect().await;
    let reply = net.send_delivered("after the reconnect").await;
    // The app's confirmed cap covers the message; the admission is reported
    // apart, bounded by B's budget in the grant.
    assert_eq!(reply["amount_msat"], 2_000, "{reply}");
    assert_eq!(reply["readmission_msat"], 2_000, "{reply}");

    // B's signed quote (2,000 msat admission) and the 2,000 msat message, twice.
    let paid = net.sender.paid_out().await;
    assert_eq!(paid, vec![2_000; 4], "admission + message, twice, at B's own quote");

    // Every payment was debited to the G1 budget, once, against B's cap.
    let grant = net.sender.grant();
    assert_eq!(grant.used_msat, 8_000);
    assert_eq!(grant.used_by_recipient.get(&bob.to_hex()), Some(&8_000));

    // N2: B refused out loud; A logged each paid re-admission with the cap.
    assert!(!net.b_codes().contains(&Code::AdmissionRequired));
    assert!(net.audit_b.membrane().pre_payment_refusals().buckets.iter().any(|b| b.counts.get(&konsensus_api::membrane::PrePaymentReason::AdmissionRequired).copied().unwrap_or(0) > 0));
    let readmissions = net.sender.membrane(Code::Readmission);
    assert_eq!(readmissions.len(), 2, "{readmissions:?}");
    for event in &readmissions {
        assert_eq!(event.paid_msat, Some(2_000));
        assert_eq!(event.cap_msat, Some(50_000));
        assert_eq!(event.counterparty.as_deref(), Some(bob.to_hex().as_str()));
    }
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contact_without_a_budget_needs_the_one_time_confirmation_once() {
    let mut net = two_nodes(|bob| Some(budget(bob, None))).await;
    let bob = net.bob_id;
    net.connect().await;

    // The grant does not budget B: the budget never pays its admission alone.
    let (status, body) = net.sender.compose(&bob, "hello").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded", "{body}");
    assert_eq!(body["reason"], "first_contact", "{body}");
    assert!(net.sender.paid_out().await.is_empty(), "nothing paid");
    assert!(net.sender.membrane(Code::Readmission).is_empty());

    // The door card: B's own signed quote, then one owner OK that also sets
    // B's budget in the grant.
    let (status, quote) = net
        .sender
        .post("/api/v1/messages/first-contact/quote", serde_json::json!({ "recipient": bob.to_hex() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!(quote["total_msat"], 14_000, "{quote}");
    let (status, grant) = net
        .sender
        .owner_confirm(
            serde_json::json!({
                "recipient": bob.to_hex(),
                "max_total_msat": quote["total_msat"],
                "contact_budget_msat": 40_000,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    net.send_delivered("hello").await;
    assert_eq!(net.sender.grant().per_recipient_msat.get(&bob.to_hex()), Some(&40_000));

    // From now on B is budgeted: the next reconnect needs no prompt.
    net.drop_and_reconnect().await;
    net.send_delivered("after the reconnect").await;
    assert_eq!(net.sender.paid_out().await.len(), 4);
    assert_eq!(net.sender.grant().used_by_recipient.get(&bob.to_hex()), Some(&8_000));
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 2);
    net.shutdown();
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_message_after_readmission_charges_admission_only_once() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;
    net.connect().await;
    net.send_delivered("before the drop").await;
    net.drop_and_reconnect().await;
    net.refuse_message.store(true, std::sync::atomic::Ordering::Release);
    let (status, body) = net.sender.compose(&bob, "message invoice refused").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["code"], "payment_settled_send_incomplete", "{body}");
    assert_eq!(body["amount_msat"], 2_000, "settled re-admission must be disclosed: {body}");
    assert_eq!(net.sender.paid_out().await, vec![2_000; 3]);
    let grant = net.sender.grant();
    assert_eq!(grant.used_msat, 6_000, "message debit must not count admission twice");
    assert_eq!(grant.used_by_recipient.get(&bob.to_hex()), Some(&6_000));
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_quote_is_reserved_into_the_grant_before_admission_pay() {
    // Sender prices locally at 2_000; recipient quotes admission=7_000 and
    // message=7_000. Both must be reserved against the grant before any pay
    // (Codex #111 finding 3) — previously admission paid then message refused.
    let net = two_nodes_with_price(|bob| Some(budget(bob, Some(50_000))), 7_000).await;
    let bob = net.bob_id;
    net.connect().await;
    let (status, body) = net.sender.compose(&bob, "higher recipient price").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 7_000, "{body}");
    assert_eq!(body["readmission_msat"], 7_000, "{body}");
    assert_eq!(net.sender.paid_out().await, vec![7_000, 7_000]);
    let grant = net.sender.grant();
    assert_eq!(grant.used_msat, 14_000);
    assert_eq!(grant.used_by_recipient.get(&bob.to_hex()), Some(&14_000));
    net.shutdown();
}


#[derive(Clone, Copy)]
enum AdmissionFailure { Failed, Unknown, SettledResponseLost, RequireZeroFee }

struct UnsettledAdmission {
    wallet: Arc<SharedMockProvider>,
    failure: AdmissionFailure,
    lost_response: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl LightningProvider for UnsettledAdmission {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        if matches!(self.failure, AdmissionFailure::RequireZeroFee) {
            assert_eq!(_cap, 0, "the caller's tighter ceiling must reach admission and message invoices");
            return self.wallet.pay_invoice_with_fee_limit(invoice, _cap).await;
        }
        self.pay_invoice(invoice).await
    }

    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.keysend(dest, amount, memo).await
    }

    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(&self, bolt11: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        use konsensus_core::traits::lightning::{LightningError, PaymentDetails, PaymentStatus};
        if matches!(self.failure, AdmissionFailure::SettledResponseLost) {
            let paid = self.wallet.pay_invoice(bolt11).await?;
            if !self.lost_response.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(LightningError::Connection("test: settled but response lost".into()));
            }
            return Ok(paid);
        }
        if matches!(self.failure, AdmissionFailure::Unknown) { return Err(LightningError::Connection("test: admission outcome unknown".into())); }
        let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
        Ok(PaymentDetails {
            payment_hash: invoice.payment_hash().to_string(), preimage: None,
            amount_msat: invoice.amount_milli_satoshis().unwrap(),
            status: PaymentStatus::Failed, direction: PaymentDirection::Outgoing,
            timestamp: 0, memo: None, fee_msat: None,
        })
    }
    async fn get_payment_status(&self, hash: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    { self.wallet.get_payment_status(hash).await }
    async fn get_balance_msat(&self) -> Result<u64, konsensus_core::traits::lightning::LightningError>
    { self.wallet.get_balance_msat().await }
    async fn is_available(&self) -> bool { true }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_admission_releases_the_undispatched_message_reservation() {
    let net = two_nodes_with_outcome(|bob| Some(budget(bob, Some(50_000))), 2_000, Some(AdmissionFailure::Failed)).await;
    let bob = net.bob_id;
    net.connect().await;
    let (status, body) = net.sender.compose(&bob, "admission failed").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(!body.to_string().contains("outcome unknown"), "terminal failure must not become unknown: {body}");
    assert_eq!(net.sender.grant().used_msat, 0, "neither leg moved money");
    assert!(net.sender.paid_out().await.is_empty());
    assert!(!net.sender.state.data_dir.as_ref().unwrap().join("admission-attempts").join(bob.to_hex()).exists());
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_admission_keeps_only_its_own_reservation() {
    let net = two_nodes_with_outcome(|bob| Some(budget(bob, Some(50_000))), 2_000, Some(AdmissionFailure::Unknown)).await;
    let bob = net.bob_id;
    net.connect().await;
    let (status, body) = net.sender.compose(&bob, "admission unknown").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(body.to_string().contains("outcome unknown"), "{body}");
    assert_eq!(net.sender.grant().used_msat, 2_000, "only admission may have dispatched");
    assert!(net.sender.paid_out().await.is_empty());
    assert!(net.sender.state.data_dir.as_ref().unwrap().join("admission-attempts").join(bob.to_hex()).exists());
    net.shutdown();
}

// The grant per-call limit covers admission plus the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_readmission_respects_aggregate_grant_per_call_limit() {
    let net = two_nodes(|bob| Some(budget(bob, Some(50_000)).per_call(3_000))).await;
    net.connect().await;
    let (status, body) = net.sender.compose(&net.bob_id, "one call").await;
    let paid: u64 = net.sender.paid_out().await.iter().sum();
    println!("compose={status} {body}; total paid={paid}; grant used={}", net.sender.grant().used_msat);
    net.shutdown();
    assert!(paid <= 3_000, "one compose exceeded the grant per-call maximum: {paid}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_recovered_admission_emits_one_n2_event() {
    let net = two_nodes_with_outcome(|bob| Some(budget(bob, Some(50_000))), 2_000,
        Some(AdmissionFailure::SettledResponseLost)).await;
    net.connect().await;
    let (status, body) = net.sender.compose(&net.bob_id, "lost response").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(net.sender.paid_out().await, vec![2_000]);
    let (status, body) = net.sender.compose(&net.bob_id, "recover").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    wait_until("recipient promoted", || privileged_on(&net.transport_b, &net.alice_id)).await;
    let events = net.sender.membrane(Code::Readmission);
    assert_eq!(events.len(), 1, "a recovered settled admission must emit its N2 event");
    assert_eq!(events[0].paid_msat, Some(2_000));
    assert_eq!(events[0].cap_msat, Some(50_000));
    let (status, body) = net.sender.compose(&net.bob_id, "already admitted").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 1, "proof reuse must not duplicate settlement");
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_readmission_preserves_zero_routing_fee_ceiling() {
    let mut net = two_nodes_with_outcome(|_| None, 2_000, Some(AdmissionFailure::RequireZeroFee)).await;
    net.connect().await;
    net.send_delivered("zero routing fees").await;
    net.drop_and_reconnect().await;
    net.send_delivered("still zero routing fees").await;
    assert_eq!(net.sender.paid_out().await.len(), 4);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_readmission_succeeds_when_quote_fits() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    // Zero-fee all-in: admission 2_000 + message 2_000.
    const CAP: u64 = 4_000;
    net.connect().await;
    net.send_delivered_capped("before the drop", CAP).await;
    net.drop_and_reconnect().await;
    let reply = net.send_delivered_capped("after the reconnect", CAP).await;
    assert_eq!(reply["amount_msat"], 2_000, "{reply}");
    assert_eq!(reply["readmission_msat"], 2_000, "{reply}");
    assert_eq!(net.sender.paid_out().await, vec![2_000; 4], "exactly one admission per connection");
    assert_eq!(net.sender.grant().used_msat, 8_000);
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 2);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_refuses_before_payment_when_quote_does_not_fit() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;
    net.connect().await;
    net.send_delivered_capped("before the drop", 4_000).await;
    net.drop_and_reconnect().await;
    // Message alone fits; admission + message does not.
    let (status, body) = net.sender.compose_capped(&bob, "too tight", 2_000).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded", "{body}");
    assert_eq!(net.sender.paid_out().await, vec![2_000; 2], "no re-admission or message paid");
    assert_eq!(net.sender.grant().used_msat, 4_000);
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 1);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_refuses_with_no_quote() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;
    net.connect().await;
    net.send_delivered_capped("before the drop", 4_000).await;
    net.drop_and_reconnect().await;
    net.refuse_admission_quote.store(true, std::sync::atomic::Ordering::Release);
    let (status, body) = net.sender.compose_capped(&bob, "no quote", 4_000).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{status} {body}");
    assert_eq!(body["code"], 502, "{body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("target refused admission quote"),
        "{body}"
    );
    assert_eq!(net.sender.paid_out().await, vec![2_000; 2], "nothing paid without a quote");
    assert_eq!(net.sender.grant().used_msat, 4_000);
    assert!(!privileged_on(&net.transport_b, &net.alice_id).await);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_respects_paired_grant_contact_limit() {
    // Contact cap covers one admission+message (4_000), not a second reconnect.
    let mut net = two_nodes(|bob| Some(budget(bob, Some(4_000)))).await;
    net.connect().await;
    net.send_delivered_capped("before the drop", 4_000).await;
    net.drop_and_reconnect().await;
    let (status, body) = net.sender.compose_capped(&net.bob_id, "grant exhausted", 4_000).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded", "{body}");
    assert_eq!(net.sender.paid_out().await, vec![2_000; 2]);
    assert_eq!(net.sender.grant().used_msat, 4_000);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_no_double_pay_on_retry_or_flap() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    const CAP: u64 = 4_000;
    net.connect().await;
    net.send_delivered_capped("first", CAP).await;
    net.drop_and_reconnect().await;
    net.send_delivered_capped("after flap", CAP).await;
    // Same live connection: retry must not buy admission again.
    let reply = net.send_delivered_capped("retry same connection", CAP).await;
    assert!(reply["readmission_msat"].is_null() || reply["readmission_msat"] == 0, "{reply}");
    assert_eq!(net.sender.paid_out().await, vec![2_000; 5], "two admissions + three messages");
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 2);
    net.drop_and_reconnect().await;
    net.send_delivered_capped("after second flap", CAP).await;
    assert_eq!(net.sender.paid_out().await.len(), 7);
    assert_eq!(net.sender.membrane(Code::Readmission).len(), 3);
    net.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_paired_send_cannot_add_unquoted_reconnection_debit() {
    let net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;
    net.connect().await;
    // Cap covers the message only (zero fee); re-admission quote does not fit.
    let (status, body) = net.sender.compose_capped(&bob, "all in", 2_000).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded");
    assert!(net.sender.paid_out().await.is_empty());
    assert_eq!(net.sender.grant().used_msat, 0);
    net.shutdown();
}

/// Real-UI 10b / app #62, the live case: after a restart the contact asks for
/// admission again. A send whose cap covers the message only is refused before
/// any payment with 409 `price_cap_exceeded` and the stable `reason`; the quote
/// it fetched stays readable on the same connection. The same operation under
/// a cap that fits pays admission once and the message once; retrying that
/// operation id pays nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_readmission_refusal_carries_a_stable_reason() {
    let mut net = two_nodes(|bob| Some(budget(bob, Some(50_000)))).await;
    let bob = net.bob_id;
    net.connect().await;
    net.send_delivered("before the drop").await;
    net.drop_and_reconnect().await;
    let paid = net.sender.paid_out().await;
    let used = net.sender.grant().used_msat;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let compose = |cap: u64| serde_json::json!({
        "recipient": bob.to_hex(), "kind": konsensus_core::kind::KIND_CHAT,
        "plaintext": "after the reconnect", "max_total_msat": cap, "max_routing_fee_msat": 0,
        "operation_id": operation_id,
    });
    // The message fits, admission on top does not: refused, nothing paid.
    for _ in 0..2 {
        let (status, body) = net.sender.post("/api/v1/messages/compose", compose(3_000)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "price_cap_exceeded", "{body}");
        assert_eq!(body["reason"], "readmission_required", "{body}");
        assert_eq!(body["operation_id"], operation_id.as_str(), "{body}");
        assert_eq!(body["state"], "prepared", "{body}");
        assert_eq!(body["retry_allowed"], true, "{body}");
        assert_eq!(body["payment_hash"], serde_json::Value::Null, "{body}");
        assert_eq!(net.sender.paid_out().await, paid);
        assert_eq!(net.sender.grant().used_msat, used);
    }
    // The owner's quote: admission once plus this message, all-in.
    let (status, quote) = net.sender.post("/api/v1/messages/first-contact/quote",
        serde_json::json!({"recipient": bob.to_hex()})).await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!((quote["admission_msat"].as_u64(), quote["message_msat"].as_u64(), quote["total_msat"].as_u64()),
        (Some(2_000), Some(2_000), Some(14_000)), "policy fee ceilings included: {quote}");
    // Same operation id under the quoted total: admission once, message once.
    let (status, body) = net.sender.post("/api/v1/messages/compose", compose(14_000)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["operation_id"], operation_id.as_str(), "{body}");
    assert_eq!(body["amount_msat"], 2_000, "{body}");
    assert_eq!(body["readmission_msat"], 2_000, "{body}");
    assert_eq!(body["max_routing_fee_msat"], 0, "{body}");
    assert_eq!(net.delivered.recv().await.as_deref(), Some("after the reconnect"));
    let mut expected = paid.clone();
    expected.extend([2_000, 2_000]);
    assert_eq!(net.sender.paid_out().await, expected);
    assert_eq!(net.sender.grant().used_msat, used + 4_000);
    // A retry of the same operation id pays nothing more.
    let (status, again) = net.sender.post("/api/v1/messages/compose", compose(14_000)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["message_id"], body["message_id"], "{again}");
    assert_eq!(net.sender.paid_out().await, expected);
    assert_eq!(net.sender.grant().used_msat, used + 4_000);
    // A second message on the same connection pays the message only.
    net.send_delivered_capped("same connection", 4_000).await;
    expected.push(2_000);
    assert_eq!(net.sender.paid_out().await, expected, "at most one admission per connection");
    net.shutdown();
}

/// Codex #111 finding 3: a higher fresh message quote must fail the grant
/// before any admission payment, not after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_refuses_when_quoted_all_in_exceeds_grant_before_pay() {
    // Sender prices locally at 2_000; recipient quotes admission=3_000 and
    // message=3_000. Cap 6_000 fits the quote; grant per_call 5_000 does not.
    let net = two_nodes_with_price(|bob| Some(budget(bob, Some(50_000)).per_call(5_000)), 3_000).await;
    net.connect().await;
    let (status, body) = net.sender.compose_capped(&net.bob_id, "higher quote", 6_000).await;
    let paid = net.sender.paid_out().await;
    net.shutdown();
    assert!(
        paid.is_empty(),
        "quote all-in=6000 grant per_call=5000 must refuse before pay; paid={paid:?}, status={status}, body={body}"
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded", "{body}");
}

/// Codex #111 finding 5: a quote obtained on a prior connection generation
/// must not be paid after reconnect when the replacement refuses fresh quotes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_reconnect_rejects_quote_from_prior_connection_generation() {
    let net = two_nodes(|_| None).await;
    net.connect().await;
    let (status, body) = net
        .sender
        .post(
            "/api/v1/messages/first-contact/quote",
            serde_json::json!({"recipient": net.bob_id.to_hex()}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.drop_and_reconnect().await;
    net.refuse_admission_quote
        .store(true, std::sync::atomic::Ordering::Release);
    let (status, body) = net
        .sender
        .compose_capped(&net.bob_id, "stale generation", 4_000)
        .await;
    let paid = net.sender.paid_out().await;
    net.shutdown();
    assert!(
        paid.is_empty(),
        "no quote on current generation may be paid; paid={paid:?}, status={status}, body={body}"
    );
}

/// #111 review finding 2: a wallet whose routing ceiling is one principal's
/// worth, recording every ceiling a dispatch was authorized with.
struct RepricingFeeProvider {
    wallet: Arc<SharedMockProvider>,
    dispatched_limits: std::sync::Mutex<Vec<u64>>,
    /// Pay the message, then lose the wallet's response to it.
    lose_message_response: bool,
}

#[async_trait::async_trait]
impl LightningProvider for RepricingFeeProvider {
    fn routing_fee_policy(&self) -> konsensus_core::traits::lightning::RoutingFeePolicy {
        konsensus_core::traits::lightning::RoutingFeePolicy {
            minimum_msat: 0,
            proportional_millionths: 1_000_000,
            maximum_msat: 10_000,
        }
    }

    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.create_invoice(amount, description, expiry).await
    }

    async fn pay_invoice(&self, bolt11: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.pay_invoice(bolt11).await
    }

    async fn pay_invoice_with_fee_limit(&self, bolt11: &str, cap: u64)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        let dispatches = {
            let mut limits = self.dispatched_limits.lock().unwrap();
            limits.push(cap);
            limits.len()
        };
        let paid = self.wallet.pay_invoice_with_fee_limit(bolt11, cap).await;
        if self.lose_message_response && dispatches == 2 {
            return Err(konsensus_core::traits::lightning::LightningError::Connection("response lost".into()));
        }
        paid
    }

    async fn get_payment_status(&self, hash: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.get_payment_status(hash).await
    }

    async fn get_balance_msat(&self)
        -> Result<u64, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.get_balance_msat().await
    }

    async fn is_available(&self) -> bool { true }
}

/// A capped send whose re-admission quote reprices the message reports the
/// routing ceilings of the admission and of the fresh message price, i.e. the
/// ones actually given to the wallet, never the stale local price's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repriced_readmission_reports_the_fee_ceilings_it_authorized() {
    // The sender's cached/local message price is 2,000. The peer quotes 3,000
    // admission + 3,000 message. The policy allows one principal's worth of
    // routing fees per dispatch, so the actual authorized sum is 6,000.
    let mut net = two_nodes_with_price(
        |bob| Some(budget(bob, Some(50_000))),
        3_000,
    ).await;
    let provider = Arc::new(RepricingFeeProvider {
        wallet: Arc::clone(&net.sender.wallet),
        dispatched_limits: std::sync::Mutex::new(Vec::new()),
        lose_message_response: false,
    });
    let mut state = (*net.sender.state).clone();
    state.lightning = provider.clone();
    net.sender.state = Arc::new(state);
    net.sender.router = konsensus_api::build_router(Arc::clone(&net.sender.state))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    net.connect().await;

    // Do not use compose_capped: it intentionally hardcodes a zero fee ceiling.
    let (status, body) = net.sender.post(
        "/api/v1/messages/compose",
        serde_json::json!({
            "recipient": net.bob_id.to_hex(),
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": "fresh price must update the reported fee allowance",
            "max_total_msat": 12_000
        }),
    ).await;
    let paid = net.sender.paid_out().await;
    let limits = provider.dispatched_limits.lock().unwrap().clone();
    let grant_used = net.sender.grant().used_msat;
    net.shutdown();

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(paid, vec![3_000, 3_000], "{body}");
    assert_eq!(limits, vec![3_000, 3_000], "{body}");
    assert_eq!(grant_used, 6_000, "mock actual routing fee is zero");
    assert_eq!(
        body["max_routing_fee_msat"],
        serde_json::json!(limits.iter().sum::<u64>()),
        "response must sum the ceilings actually authorized for admission and the freshly priced message"
    );
}

/// The same repricing when the message's outcome is unknown: the error still
/// reports the ceilings given to the wallet (admission + fresh message price).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repriced_readmission_error_reports_the_fee_ceilings_it_authorized() {
    let mut net = two_nodes_with_price(|bob| Some(budget(bob, Some(50_000))), 3_000).await;
    let provider = Arc::new(RepricingFeeProvider {
        wallet: Arc::clone(&net.sender.wallet),
        dispatched_limits: std::sync::Mutex::new(Vec::new()),
        lose_message_response: true,
    });
    let mut state = (*net.sender.state).clone();
    state.lightning = provider.clone();
    net.sender.state = Arc::new(state);
    net.sender.router = konsensus_api::build_router(Arc::clone(&net.sender.state))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    net.connect().await;
    let (status, body) = net.sender.post(
        "/api/v1/messages/compose",
        serde_json::json!({
            "recipient": net.bob_id.to_hex(),
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": "fresh price, unknown outcome",
            "max_total_msat": 12_000
        }),
    ).await;
    let limits = provider.dispatched_limits.lock().unwrap().clone();
    net.shutdown();
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["state"], "payment_unknown", "{body}");
    assert_eq!(limits, vec![3_000, 3_000], "{body}");
    assert_eq!(body["max_routing_fee_msat"], serde_json::json!(6_000), "{body}");
}
