use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_crypto::SessionManager;
use konsensus_message::{NoiseTransport, ReachabilityMode, TransportConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use tower::ServiceExt;
const JWT_SECRET: &str = "disposable-regtest-jwt-secret";
type InvoiceRequests = Arc<
    tokio::sync::Mutex<
        HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceRequestOutcome>>,
    >,
>;
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
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let proof = key.sign(&PairingService::proof_message(
        &outcome.pair_id,
        &pubkey,
        &challenge,
    ));
    let client = service
        .confirm_pairing(
            &outcome.pair_id,
            &hex::encode(proof.to_bytes()),
            pairing::default_pairing_scopes(),
        )
        .unwrap();

    let pending = service
        .create_budget_elevation_request(
            &client.client_id,
            vec![konsensus_api::auth::Scope::Spend],
            None,
        )
        .unwrap();
    let phrase = console.confirmation(&pairing::grant_confirmation_phrase(&pending));
    service
        .grant_elevation(&pending.op_id, &phrase, terms)
        .unwrap();

    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let signature = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let token = service
        .issue_token(
            &node.node_id().to_hex(),
            JWT_SECRET,
            &client.client_id,
            &challenge,
            &signature,
        )
        .unwrap()
        .token;
    (service, client.client_id, token)
}

pub struct App {
    pub state: Arc<konsensus_api::AppState>,
    pub transport: Arc<NoiseTransport>,
    pub received: tokio::sync::broadcast::Receiver<Arc<konsensus_api::state::WsMessage>>,
    router: axum::Router,
    token: String,
    pub service: Arc<konsensus_api::pairing::PairingService>,
    pub client: String,
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for App {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.transport.shutdown();
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl App {
    pub async fn start(
        dir: &std::path::Path,
        chain: &infra::Chain,
        wallet: Arc<LdkProvider>,
    ) -> Self {
        let identity = &Arc::new(NodeIdentity::generate().unwrap().1);
        let transport = &Arc::new(NoiseTransport::new(
            identity.clone(),
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                ..Default::default()
            },
        ));
        transport.start_listener().await.unwrap();
        let sessions = &Arc::new(SessionManager::new(identity.clone()));
        let pairing = paired_client(
            &dir.join("pairing"),
            identity,
            konsensus_api::spend_budget::GrantTerms::new(1_000_000)
                .per_call(200_000)
                .for_secs(3600),
        );
        let invoice_requests: InvoiceRequests = Default::default();
        let state = Arc::new(konsensus_api::AppState {
            identity: Arc::clone(identity),
            storage: Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap()),
            lightning: wallet.clone(),
            chain: Arc::new(
                konsensus_chain::EsploraProvider::new(konsensus_chain::EsploraConfig::custom(
                    chain.api_url.clone(),
                    konsensus_core::traits::chain::TrustLevel::FullValidation,
                ))
                .unwrap(),
            ),
            pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(
                konsensus_pricing::StaticPricingConfig {
                    chat_msat: 2_001,
                    ..Default::default()
                },
            )),
            gate: Arc::new(konsensus_core::PaymentGate::new()),
            peer_registry: Arc::new(tokio::sync::RwLock::new(
                konsensus_message::PeerRegistry::new(),
            )),
            transport: Arc::clone(transport) as Arc<dyn MessageTransport>,
            session_manager: Arc::clone(sessions),
            jwt_secret: JWT_SECRET.into(),
            auth_challenges: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pairing: Some(pairing.0.clone()),
            cors_enabled: false,
            operator_probes_enabled: true,
            sensitive_identity_routes_enabled: true,
            has_identity_passphrase: false,
            ws_broadcast: tokio::sync::broadcast::channel(16).0,
            ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
            rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
            mnemonic_reveal_limiter: Arc::new(
                konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default(),
            ),
            audit_log: Arc::new(
                konsensus_api::audit::AuditLog::open(dir.join("audit.log")).unwrap(),
            ),
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
            lightning_backend: "ldk".into(),
            chain_backend: "esplora".into(),
            // A dialable loopback endpoint on regtest, so a front-door card
            // can be issued and knocked on.
            introduction: konsensus_api::handlers::introduction::IntroductionSettings::fixed(
                Some("regtest"),
                transport.listen_addr().map(|a| a.to_string()).as_deref(),
            ),
            front_door: Default::default(),
            sponsor: Default::default(),
            stun_port: None,
            custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
            gossip_validator: None,
            file_staging: Default::default(),
        });

        let expected_height: u64 = chain.bitcoin.client.call("getblockcount", &[]).unwrap();
        assert_eq!(
            state
                .chain
                .get_block_height()
                .await
                .expect("application chain endpoint"),
            expected_height
        );
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (pending_tx, _pending_rx) = tokio::sync::mpsc::channel(64);
        let (auto_channel_tx, _auto_channel_rx) = tokio::sync::mpsc::channel(64);
        let session = tokio::spawn(crate::session_handler::run(
            crate::session_handler::SessionHandlerDeps {
                transport: transport.clone(),
                session_manager: sessions.clone(),
                storage: state.storage.clone(),
                our_node_id: *identity.node_id(),
                identity: identity.clone(),
                audit_log: state.audit_log.clone(),
                pricing: state.pricing.clone(),
                chain: state.chain.clone(),
                peer_prices: state.peer_prices.clone(),
                peer_registry: state.peer_registry.clone(),
                routing: state.routing.clone(),
                gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(
                    Default::default(),
                )),
                send_timestamps: state.send_timestamps.clone(),
                lightning: state.lightning.clone(),
                lightning_addr: None,
                mock_lightning: false,
                invoice_requests: state.invoice_requests.clone(),
                peer_ln_pubkeys: state.peer_ln_pubkeys.clone(),
                ws_broadcast: state.ws_broadcast.clone(),
                ws_delivery_tx: state.ws_delivery_broadcast.clone(),
                pending_tx,
                auto_channel_tx,
                shutdown_rx: shutdown_rx.clone(),
            },
        ));
        let messages = tokio::spawn(crate::msg_handler::run(
            crate::msg_handler::MsgHandlerDeps {
                transport: transport.clone(),
                transport_ack: transport.clone(),
                storage: state.storage.clone(),
                gate: state.gate.clone(),
                pricing: state.pricing.clone(),
                lightning: state.lightning.clone(),
                chain: state.chain.clone(),
                peer_registry: state.peer_registry.clone(),
                session_manager: sessions.clone(),
                nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(
                    state.storage.clone(),
                )),
                content_server: None,
                front_door: state.front_door.clone(),
                routing: state.routing.clone(),
                identity: identity.clone(),
                plaintext_cipher: Arc::new(konsensus_crypto::PlaintextCacheCipher::new(
                    identity.aes_key(),
                )),
                ws_tx: state.ws_broadcast.clone(),
                audit_log: state.audit_log.clone(),
                admission_mode: ReachabilityMode::PriceOpen,
                relay_engine: None,
                shutdown_rx,
            },
        ));
        let router = konsensus_api::build_router(state.clone()).layer(
            axum::extract::connect_info::MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))),
        );
        let (service, client, token) = pairing;
        Self {
            received: state.ws_broadcast.subscribe(),
            state,
            transport: transport.clone(),
            router,
            service,
            client,
            token,
            shutdown,
            tasks: vec![session, messages],
        }
    }

    pub async fn post(&self, uri: &str, body: Value, owner: bool) -> (StatusCode, Value) {
        self.request("POST", uri, Some(body), owner).await
    }
    pub async fn put(&self, uri: &str, body: Value, owner: bool) -> (StatusCode, Value) {
        self.request("PUT", uri, Some(body), owner).await
    }
    pub async fn get(&self, uri: &str, owner: bool) -> (StatusCode, Value) {
        self.request("GET", uri, None, owner).await
    }
    async fn request(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        owner: bool,
    ) -> (StatusCode, Value) {
        let token = if owner {
            konsensus_api::auth::create_token(
                &self.state.identity.node_id().to_hex(),
                JWT_SECRET,
                konsensus_api::auth::Scope::all(),
            )
            .unwrap()
        } else {
            self.token.clone()
        };
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    pub fn used(&self) -> u64 {
        self.service.grant_view_for(&self.client).unwrap().used_msat
    }
    pub async fn compose(&self, receiver: &mut Self, text: &str) -> Value {
        let started = std::time::Instant::now();
        let (status, body) = self
            .post(
                "/api/v1/messages/compose",
                json!({
                    "recipient": receiver.state.identity.node_id().to_hex(), "kind": 0,
                    "plaintext": text
                }),
                false,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "compose: {body}");
        assert_eq!(body["delivered"], true, "{body}");
        let message = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let message = receiver.received.recv().await.unwrap();
                // The receiver's feed also echoes its own outbound messages.
                if message.envelope.sender != *self.state.identity.node_id() {
                    continue;
                }
                if message.envelope.ciphertext == b"konsensus:admission:v1" {
                    assert!(
                        message.plaintext.is_none(),
                        "admission marker is not E2EE content"
                    );
                    continue;
                }
                return message;
            }
        })
        .await
        .unwrap();
        assert_eq!(message.plaintext.as_deref(), Some(text));
        assert_ne!(message.envelope.ciphertext, text.as_bytes());
        println!("compose {text:?}: {:?} {body}", started.elapsed());
        body
    }
}
