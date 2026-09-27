//! Two-node regression for the reconnect bug (UI-E2E run 7): after a paid
//! admission, a reconnect demoted the sender to a stranger and the recipient
//! then dropped its message-invoice requests in silence, so every send timed
//! out after 30 s.
//!
//! Real pieces: two Noise transports over loopback (the recipient in
//! `price_open`), node A's `POST /api/v1/messages/compose` route, node B's
//! invoice handler and payment gate with promote-on-paid, both N2 membranes,
//! and each side's invoice bookkeeping. The stand-ins: one in-memory
//! Lightning ledger both wallets share, and the E2EE sessions, set up directly
//! (in the field X3DH runs after the first admission, and both sides keep the
//! session across a reconnect).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tower::ServiceExt;

use konsensus_api::membrane::Code;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::SessionManager;
use konsensus_message::{ControlEvent, NoiseTransport, ReachabilityMode, TransportConfig};

use super::{
    handle_invoice_error_received, handle_invoice_requested_gated, handle_invoice_response,
    InvoiceRequestOutcome,
};

/// The marker node A's compose puts in an admission envelope (not E2EE).
const ADMISSION_MARKER: &[u8] = b"konsensus:admission:v1";

// ── A Lightning ledger both test wallets settle through ─────────────────

#[derive(Default)]
struct Ledger {
    /// payment hash (hex) → (preimage, amount, settled)
    invoices: HashMap<String, ([u8; 32], u64, bool)>,
}

/// One node's wallet on the shared ledger. It issues real BOLT11 invoices
/// (compose parses them) and reports its own side of each payment.
struct TestWallet {
    ledger: Arc<std::sync::Mutex<Ledger>>,
    created: std::sync::Mutex<HashSet<String>>,
    paid: std::sync::Mutex<Vec<(String, u64)>>,
}

impl TestWallet {
    fn new(ledger: &Arc<std::sync::Mutex<Ledger>>) -> Self {
        Self {
            ledger: Arc::clone(ledger),
            created: std::sync::Mutex::new(HashSet::new()),
            paid: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn payments_made(&self) -> Vec<(String, u64)> {
        self.paid.lock().unwrap().clone()
    }
}

fn bolt11(amount_msat: u64, preimage: &[u8; 32]) -> (String, String) {
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("konsensus test".into())
        .payment_hash(sha256::Hash::from_byte_array(hash))
        .payment_secret(PaymentSecret(rand::random()))
        .current_timestamp()
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(amount_msat)
        .build_signed(|msg| {
            let secp = secp256k1::Secp256k1::new();
            let key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
            secp.sign_ecdsa_recoverable(msg, &key)
        })
        .unwrap();
    (invoice.to_string(), hex::encode(hash))
}

#[async_trait]
impl LightningProvider for TestWallet {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let preimage: [u8; 32] = rand::random();
        let (bolt11, payment_hash) = bolt11(amount_msat, &preimage);
        self.ledger
            .lock()
            .unwrap()
            .invoices
            .insert(payment_hash.clone(), (preimage, amount_msat, false));
        self.created.lock().unwrap().insert(payment_hash.clone());
        Ok(Invoice {
            bolt11,
            payment_hash,
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: 0,
        })
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let invoice: lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| LightningError::PaymentFailed(format!("bad invoice: {e:?}")))?;
        let payment_hash = hex::encode(invoice.payment_hash());
        let (preimage, amount_msat) = {
            let mut ledger = self.ledger.lock().unwrap();
            let entry = ledger
                .invoices
                .get_mut(&payment_hash)
                .ok_or_else(|| LightningError::PaymentFailed("unknown invoice".into()))?;
            entry.2 = true;
            (entry.0, entry.1)
        };
        self.paid.lock().unwrap().push((payment_hash.clone(), amount_msat));
        Ok(PaymentDetails {
            payment_hash,
            preimage: Some(hex::encode(preimage)),
            amount_msat,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: 0,
            memo: None,
            fee_msat: None,
        })
    }

    async fn get_payment_status(&self, payment_hash: &str) -> Result<PaymentDetails, LightningError> {
        let (preimage, amount_msat, settled) = *self
            .ledger
            .lock()
            .unwrap()
            .invoices
            .get(payment_hash)
            .ok_or_else(|| LightningError::PaymentFailed("unknown payment".into()))?;
        let direction = if self.created.lock().unwrap().contains(payment_hash) {
            PaymentDirection::Incoming
        } else {
            PaymentDirection::Outgoing
        };
        Ok(PaymentDetails {
            payment_hash: payment_hash.to_string(),
            preimage: settled.then(|| hex::encode(preimage)),
            amount_msat,
            status: if settled { PaymentStatus::Settled } else { PaymentStatus::Pending },
            direction,
            timestamp: 0,
            memo: None,
            fee_msat: None,
        })
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(100_000_000)
    }

    async fn is_available(&self) -> bool {
        true
    }
}

// ── Node wiring ─────────────────────────────────────────────────────────

fn identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").unwrap())
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
    Arc::new(konsensus_pricing::StaticPricingEngine::new(
        konsensus_pricing::StaticPricingConfig::default(),
    ))
}

async fn storage() -> Arc<dyn konsensus_storage::Storage> {
    Arc::new(konsensus_storage::sqlite::SqliteStorage::in_memory().await.unwrap())
}

fn audit_log() -> Arc<konsensus_api::audit::AuditLog> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    Arc::new(konsensus_api::audit::AuditLog::open(tmp.path()).unwrap())
}

type InvoiceRequests =
    Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>>;

/// Node A: the sender, driven through its real compose route.
struct Sender {
    router: axum::Router,
    auth: String,
    wallet: Arc<TestWallet>,
}

async fn start_sender(
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    sessions: &Arc<SessionManager>,
    wallet: Arc<TestWallet>,
) -> Sender {
    let invoice_requests: InvoiceRequests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let state = Arc::new(konsensus_api::AppState {
        file_staging: Default::default(),
        identity: Arc::clone(identity),
        storage: storage().await,
        lightning: Arc::clone(&wallet) as Arc<dyn LightningProvider>,
        chain: Arc::new(konsensus_chain::mock::MockChainProvider::new()),
        pricing: pricing(),
        gate: Arc::new(konsensus_core::PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(konsensus_message::PeerRegistry::new())),
        transport: Arc::clone(transport) as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(sessions),
        jwt_secret: "reconnect-regression-jwt-secret".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pairing: None,
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(
            konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default(),
        ),
        audit_log: audit_log(),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
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

    let token = konsensus_api::auth::create_token(
        &identity.node_id().to_hex(),
        &state.jwt_secret,
        konsensus_api::auth::Scope::all(),
    )
    .unwrap();
    let router = konsensus_api::build_router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    Sender { router, auth: format!("Bearer {token}"), wallet }
}

impl Sender {
    async fn compose(&self, recipient: &NodeId, text: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/messages/compose")
            .header("authorization", &self.auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "recipient": recipient.to_hex(),
                    "kind": konsensus_core::kind::KIND_CHAT,
                    "plaintext": text,
                })
                .to_string(),
            ))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }
}

/// Node B: the `price_open` recipient. Returns its membrane and the plaintexts
/// it delivers, in order.
async fn start_recipient(
    identity: &Arc<NodeIdentity>,
    transport: &Arc<NoiseTransport>,
    sessions: &Arc<SessionManager>,
    wallet: Arc<TestWallet>,
) -> (Arc<konsensus_api::audit::AuditLog>, mpsc::UnboundedReceiver<String>) {
    let audit = audit_log();
    let lightning: Arc<dyn LightningProvider> = wallet;
    let pricing = pricing();

    // B's control plane: invoice requests, through the real privilege gate.
    {
        let transport = Arc::clone(transport);
        let audit = Arc::clone(&audit);
        let lightning = Arc::clone(&lightning);
        let pricing = Arc::clone(&pricing);
        let recipient = *identity.node_id();
        tokio::spawn(async move {
            let mut last_refusal = HashMap::new();
            let mut quotes = crate::admission_quotes::AdmissionQuotes::default();
            while let Some(event) = transport.recv_control().await {
                if let ControlEvent::InvoiceRequested { peer_id, request_id, amount_msat, purpose, privileged, source_ip } = event {
                    handle_invoice_requested_gated(
                        &peer_id, &request_id, amount_msat, &purpose, privileged,
                        &pricing, &lightning, &transport, &recipient, source_ip, &mut quotes, audit.membrane(), &mut last_refusal,
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

// ── The regression ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_message_after_reconnect_is_delivered_not_silently_dropped() {
    let alice = identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let bob = identity("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    let (alice_id, bob_id) = (*alice.node_id(), *bob.node_id());

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

    let ledger = Arc::new(std::sync::Mutex::new(Ledger::default()));
    let sender = start_sender(&alice, &transport_a, &sessions_a, Arc::new(TestWallet::new(&ledger))).await;
    let (audit_b, mut delivered) =
        start_recipient(&bob, &transport_b, &sessions_b, Arc::new(TestWallet::new(&ledger))).await;

    // 1. Admit: A connects as a stranger; its first paid message pays admission.
    transport_a.connect(&bob_id, &addr_b).await.unwrap();
    wait_until("B sees A", || transport_b.is_connected(&alice_id)).await;
    assert!(!privileged_on(&transport_b, &alice_id).await, "a new connection starts unpaid");

    let (status, body) = sender.compose(&bob_id, "before the drop").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "{body}");
    assert_eq!(delivered.recv().await.as_deref(), Some("before the drop"));
    assert!(privileged_on(&transport_b, &alice_id).await, "admission promoted A's connection");

    // 2. Drop the connection, 3. reconnect: B holds A as unpaid again (doctrine:
    //    no durable admission object).
    transport_b.disconnect(&alice_id).await.unwrap();
    wait_until("A sees the drop", || async { !transport_a.is_connected(&bob_id).await }).await;
    transport_a.connect(&bob_id, &addr_b).await.unwrap();
    wait_until("B sees A again", || transport_b.is_connected(&alice_id)).await;
    assert!(!privileged_on(&transport_b, &alice_id).await, "a reconnect starts unpaid");

    // 4. The next paid message is delivered, promptly, on the same E2EE session.
    let started = std::time::Instant::now();
    let (status, body) = sender.compose(&bob_id, "after the reconnect").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "{body}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "no silent drop: the refusal is answered at once, not by a 30 s timeout ({:?})",
        started.elapsed()
    );
    assert_eq!(delivered.recv().await.as_deref(), Some("after the reconnect"));
    assert!(privileged_on(&transport_b, &alice_id).await, "re-admission promoted the new connection");

    // Each act re-proven: two admissions and two messages, nothing paid twice.
    let payments = sender.wallet.payments_made();
    assert_eq!(payments.len(), 4, "admission + message, twice: {payments:?}");
    let unique: HashSet<_> = payments.iter().map(|(hash, _)| hash).collect();
    assert_eq!(unique.len(), 4, "no invoice paid twice");

    // B refused out loud (N2) and never saw a replayed admission proof.
    let (events, totals) = audit_b.membrane().read(None, 50);
    let codes: Vec<Code> = events.iter().map(|e| e.code).collect();
    assert!(codes.contains(&Code::AdmissionRequired), "explicit refusal event: {codes:?}");
    assert!(!codes.contains(&Code::ProofReused), "stale admission proof re-sent: {codes:?}");
    assert_eq!(totals.admitted, 4, "two admissions and two messages admitted: {codes:?}");

    transport_a.shutdown();
    transport_b.shutdown();
}
