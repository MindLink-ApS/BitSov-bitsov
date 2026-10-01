use super::*;
use konsensus_core::types::{MessageId, Nonce, PaymentProof};
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::peer::PeerEntry;
use konsensus_storage::{SqliteStorage, StorageNonceAdapter};
use std::sync::Arc;

tokio::task_local! {
    // Scoped to one future so advancing quote time cannot affect parallel tests.
    pub(super) static CLOCK: u64;
}

struct Fixture {
    _dir: tempfile::TempDir,
    owner: Arc<NodeIdentity>,
    payer: Arc<NodeIdentity>,
    receiver: Arc<SharedMockProvider>,
    sender: SharedMockProvider,
    registry: Arc<tokio::sync::RwLock<PeerRegistry>>,
    policy: PrivacyConfig,
    pricing: konsensus_pricing::StaticPricingEngine,
    nonces: StorageNonceAdapter<SqliteStorage>,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (_, owner) = NodeIdentity::generate().unwrap();
        let (_, payer) = NodeIdentity::generate().unwrap();
        let db = dir.path().join("ledger.sqlite");
        let receiver = SharedMockProvider::new(&db, "receiver", 0).unwrap();
        let sender = SharedMockProvider::new(&db, "sender", 1_000_000).unwrap();
        let mut registry = PeerRegistry::new();
        for n in 1..=55 {
            registry.add(PeerEntry {
                node_id: NodeId::from_bytes([n; 32]),
                addr: format!("192.0.2.{n}:9735").parse().unwrap(),
                label: Some(format!("private-{n}")),
                auto_connect: false,
            });
        }
        Self {
            _dir: dir,
            owner: Arc::new(owner),
            payer: Arc::new(payer),
            receiver: Arc::new(receiver),
            sender,
            registry: Arc::new(tokio::sync::RwLock::new(registry)),
            policy: PrivacyConfig {
                peer_exchange: PeerExchangeMode::Paid,
                shareable_peers: vec![NodeId::from_bytes([2; 32]), NodeId::from_bytes([3; 32])],
                share_peer_labels: vec![NodeId::from_bytes([3; 32])],
            },
            pricing: konsensus_pricing::StaticPricingEngine::new(Default::default()),
            nonces: StorageNonceAdapter::new(Arc::new(SqliteStorage::in_memory().await.unwrap())),
        }
    }
    async fn quote(&self) -> Result<PeerExchangeQuote, String> {
        issue_quote(
            &self.policy,
            &self.registry,
            *self.payer.node_id(),
            &self.owner,
            &self.pricing,
            2500,
            self.receiver.as_ref(),
        )
        .await
    }
    async fn paid(&self, q: &PeerExchangeQuote) -> UkmEnvelope {
        let paid = self.sender.pay_invoice(&q.bolt11).await.unwrap();
        let ciphertext = q.signature.as_bytes().to_vec();
        let nonce = Nonce::generate();
        let mut envelope = UkmEnvelope {
            id: MessageId::compute(&ciphertext, &nonce),
            kind: KIND_PEER_EXCHANGE,
            sender: *self.payer.node_id(),
            recipient: Recipient::Node(*self.owner.node_id()),
            timestamp: now() * 1000,
            ciphertext,
            payment_proof: PaymentProof {
                payment_hash: hex::decode(paid.payment_hash).unwrap().try_into().unwrap(),
                preimage: hex::decode(paid.preimage.unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount_msat: paid.amount_msat,
            },
            signature: Signature::from_bytes([0; 64]),
            nonce,
            references: vec![],
        };
        self.sign(&mut envelope);
        envelope
    }
    fn sign(&self, envelope: &mut UkmEnvelope) {
        envelope.signature = Signature::from_ed25519(&self.payer.sign(&envelope.signable_bytes()));
    }
    async fn redeem(
        &self,
        q: &PeerExchangeQuote,
        e: &UkmEnvelope,
    ) -> Result<Vec<PeerExchangeEntry>, String> {
        redeem(
            q,
            e,
            self.payer.node_id(),
            &self.owner,
            &self.nonces,
            self.receiver.as_ref(),
        )
        .await
    }
}

#[tokio::test]
async fn default_off_and_no_shareable_refuse_before_any_invoice_or_payment() {
    let mut f = Fixture::new().await;
    f.policy = toml::from_str("").unwrap();
    assert_eq!(f.quote().await.unwrap_err(), "peer_exchange_off");
    f.policy.peer_exchange = PeerExchangeMode::Paid;
    assert_eq!(f.quote().await.unwrap_err(), "no_shareable_peers");
    assert_eq!(f.receiver.get_balance_msat().await.unwrap(), 0);
    assert_eq!(f.sender.get_balance_msat().await.unwrap(), 1_000_000);
    assert!(f.receiver.list_payments(100).await.unwrap().is_empty());
}

#[tokio::test]
async fn paid_quote_exports_only_selected_records_and_explicit_labels_even_after_switch_off() {
    let mut f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    assert_eq!(q.amount_msat, 2500);
    assert!(q.expires_at <= now() + 60);
    f.owner
        .verify(&q.signable_bytes(), &q.signature.to_ed25519())
        .unwrap();
    assert!(!String::from_utf8_lossy(&q.snapshot).contains("private-3"));
    assert!(
        f.receiver.list_payments(100).await.unwrap().is_empty(),
        "quote creates no invoice ledger row"
    );
    let e = f.paid(&q).await;
    f.policy = PrivacyConfig::default();
    *f.registry.write().await = PeerRegistry::new();
    let mut peers = f.redeem(&q, &e).await.unwrap();
    peers.sort_by_key(|p| p.node_id.to_string());
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].node_id, NodeId::from_bytes([2; 32]));
    assert_eq!(peers[0].label, None);
    assert_eq!(peers[1].node_id, NodeId::from_bytes([3; 32]));
    assert_eq!(peers[1].label.as_deref(), Some("private-3"));
    assert_eq!(f.receiver.get_balance_msat().await.unwrap(), 2500);
    assert!(
        f.redeem(&q, &e).await.is_err(),
        "same payment cannot buy a second act"
    );
    let mut fresh = e.clone();
    fresh.nonce = Nonce::generate();
    fresh.id = MessageId::compute(&fresh.ciphertext, &fresh.nonce);
    f.sign(&mut fresh);
    assert!(
        f.redeem(&q, &fresh).await.is_err(),
        "fresh nonce cannot reuse payment"
    );
}

#[tokio::test]
async fn quote_caps_response_at_fifty() {
    let mut f = Fixture::new().await;
    f.policy.shareable_peers = (1..=55).map(|n| NodeId::from_bytes([n; 32])).collect();
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    assert_eq!(f.redeem(&q, &e).await.unwrap().len(), 50);
}

#[tokio::test]
async fn altered_expired_wrong_recipient_and_wrong_act_quotes_do_not_consume_payment() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let mut bad = q.clone();
    bad.expires_at = now() - 1;
    bad.signature = Signature::from_ed25519(&f.owner.sign(&bad.signable_bytes()));
    assert!(f.redeem(&bad, &e).await.is_err());
    let mut bad = q.clone();
    bad.snapshot[15] ^= 1;
    assert!(f.redeem(&bad, &e).await.is_err());
    let mut bad = q.clone();
    bad.recipient = *f.payer.node_id();
    assert!(f.redeem(&bad, &e).await.is_err());
    let mut bad = e.clone();
    bad.kind = 0;
    f.sign(&mut bad);
    assert!(f.redeem(&q, &bad).await.is_err());
    let mut bad = e.clone();
    bad.recipient = Recipient::Broadcast;
    f.sign(&mut bad);
    assert!(f.redeem(&q, &bad).await.is_err());
    let other = f.quote().await.unwrap();
    assert!(
        f.redeem(&other, &e).await.is_err(),
        "settled payment must match this quote"
    );
    assert!(
        f.redeem(&q, &e).await.is_ok(),
        "invalid attempts did not consume proof"
    );
}

#[tokio::test]
async fn redeem_rejects_payload_not_bound_to_quote_signature() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let mut bad = e.clone();
    bad.ciphertext[0] ^= 1;
    // Keep the envelope valid for the gate; only its binding to the quote differs.
    bad.id = MessageId::compute(&bad.ciphertext, &bad.nonce);
    f.sign(&mut bad);

    assert_eq!(
        f.redeem(&q, &bad).await.unwrap_err(),
        "quote_payment_mismatch"
    );
    assert!(f.redeem(&q, &e).await.is_ok(), "proof was not consumed");
}

#[tokio::test]
async fn redeem_rejects_genuine_quote_after_expiry() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;

    // Advance only the quote clock, leaving the genuine quote, its signature,
    // settled invoice and fresh envelope untouched. No other check can mask expiry.
    let result = CLOCK.scope(q.expires_at + 1, f.redeem(&q, &e)).await;
    assert_eq!(result.unwrap_err(), "invalid_peer_exchange_quote");
    assert!(f.redeem(&q, &e).await.is_ok(), "proof was not consumed");
}

#[tokio::test]
async fn redeem_rejects_forged_signable_fields_with_original_signature() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let mut forged = q.clone();
    // This remains inside the valid time window and changes neither the invoice
    // nor the sealed snapshot. Only Ed25519 verification can detect the forgery.
    forged.expires_at -= 1;

    assert_eq!(
        f.redeem(&forged, &e).await.unwrap_err(),
        "invalid_peer_exchange_quote"
    );
    assert!(f.redeem(&q, &e).await.is_ok(), "proof was not consumed");
}

#[tokio::test]
async fn redeem_rejects_valid_quote_reused_by_another_peer() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let (_, other_peer) = NodeIdentity::generate().unwrap();
    let mut reused = e.clone();
    // Peer B authenticates its own envelope carrying A's settled proof and the
    // original quote signature, so neither sender nor envelope verification masks it.
    reused.sender = *other_peer.node_id();
    reused.signature = Signature::from_ed25519(&other_peer.sign(&reused.signable_bytes()));

    assert_eq!(
        redeem(
            &q,
            &reused,
            other_peer.node_id(),
            &f.owner,
            &f.nonces,
            f.receiver.as_ref(),
        )
        .await
        .unwrap_err(),
        "invalid_peer_exchange_quote"
    );
    assert!(f.redeem(&q, &e).await.is_ok(), "proof was not consumed");
}

#[tokio::test]
async fn settled_payment_for_another_quote_cannot_buy_this_act() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    // A different settled invoice cannot stand in for this quote.
    let other = f.quote().await.unwrap();
    let mut e = f.paid(&other).await;
    e.ciphertext = q.signature.as_bytes().to_vec();
    e.id = MessageId::compute(&e.ciphertext, &e.nonce);
    f.sign(&mut e);
    assert!(f.redeem(&q, &e).await.is_err());
}

async fn worker(
    f: &Fixture,
    whitelisted: bool,
) -> (
    Arc<konsensus_message::NoiseTransport>,
    Arc<konsensus_message::NoiseTransport>,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    use konsensus_message::{NoiseTransport, ReachabilityMode, TransportConfig};
    use tokio::sync::{broadcast, mpsc, watch};
    let transport = |id: Arc<NodeIdentity>, other: NodeId| {
        Arc::new(NoiseTransport::new(
            id,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: if whitelisted {
                    ReachabilityMode::Whitelist
                } else {
                    ReachabilityMode::PriceOpen
                },
                whitelist: if whitelisted { vec![other] } else { vec![] },
                ..Default::default()
            },
        ))
    };
    let source = transport(f.payer.clone(), *f.owner.node_id());
    let target = transport(f.owner.clone(), *f.payer.node_id());
    target.start_listener().await.unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (ws, _) = broadcast::channel(8);
    let (delivery, _) = broadcast::channel(8);
    let (pending, _) = mpsc::channel(8);
    let (auto, _) = mpsc::channel(8);
    let handle = tokio::spawn(crate::session_handler::run(
        crate::session_handler::SessionHandlerDeps {
            privacy: f.policy.clone(),
            peer_exchange_floor: 2500,
            transport: target.clone(),
            session_manager: Arc::new(konsensus_crypto::SessionManager::new(f.owner.clone())),
            storage: Arc::new(SqliteStorage::in_memory().await.unwrap()),
            our_node_id: *f.owner.node_id(),
            identity: f.owner.clone(),
            audit_log: Arc::new(
                konsensus_api::audit::AuditLog::open(f._dir.path().join("audit.jsonl")).unwrap(),
            ),
            pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(
                Default::default(),
            )),
            chain: Arc::new(konsensus_chain::MockChainProvider::new()),
            peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
            peer_registry: f.registry.clone(),
            routing: Arc::new(konsensus_routing::RoutingTable::new(Default::default())),
            gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(Default::default())),
            send_timestamps: Default::default(),
            lightning: f.receiver.clone(),
            lightning_addr: None,
            mock_lightning: false,
            invoice_requests: Default::default(),
            peer_ln_pubkeys: Default::default(),
            ws_broadcast: ws,
            ws_delivery_tx: delivery,
            pending_tx: pending,
            auto_channel_tx: auto,
            shutdown_rx,
        },
    ));
    use konsensus_core::traits::transport::MessageTransport;
    source
        .connect(
            f.owner.node_id(),
            &target.listen_addr().unwrap().to_string(),
        )
        .await
        .unwrap();
    (source, target, shutdown, handle)
}

async fn response(source: &konsensus_message::NoiseTransport) -> Frame {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match source.recv_control().await.unwrap() {
                konsensus_message::ControlEvent::PeerExchangeAct { frame, .. } => return *frame,
                konsensus_message::ControlEvent::PeerExchangeReceived { peers, .. } => {
                    return Frame::PeerExchangeResponse { peers }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("peer exchange reply")
}

#[tokio::test]
async fn whitelist_privilege_refuses_unpaid_exchange_and_paid_wire_act_is_served() {
    let mut f = Fixture::new().await;
    f.policy.shareable_peers = (1..=55).map(|n| NodeId::from_bytes([n; 32])).collect();
    let (source, target, shutdown, handle) = worker(&f, true).await;
    source
        .send_frame(f.owner.node_id(), &Frame::PeerExchangeRequest)
        .await
        .unwrap();
    assert!(matches!(
        response(&source).await,
        Frame::PeerExchangeRefused { .. }
    ));
    assert!(target
        .connected_privileged_peers()
        .await
        .contains(f.payer.node_id()));
    source
        .send_frame(f.owner.node_id(), &Frame::PeerExchangeQuoteRequest)
        .await
        .unwrap();
    let Frame::PeerExchangeQuote { quote } = response(&source).await else {
        panic!("signed quote")
    };
    // A second quote is refused BEFORE payment; the first remains redeemable.
    source
        .send_frame(f.owner.node_id(), &Frame::PeerExchangeQuoteRequest)
        .await
        .unwrap();
    assert!(
        matches!(response(&source).await, Frame::PeerExchangeRefused { reason } if reason == "quote_rate_limited")
    );
    assert_eq!(f.sender.get_balance_msat().await.unwrap(), 1_000_000);
    assert_eq!(f.receiver.get_balance_msat().await.unwrap(), 0);
    let e = f.paid(&quote).await;
    source
        .send_frame(
            f.owner.node_id(),
            &Frame::PeerExchangePaidRequest {
                quote,
                envelope: Box::new(e),
            },
        )
        .await
        .unwrap();
    let Frame::PeerExchangeResponse { peers } = response(&source).await else {
        panic!("paid response")
    };
    assert_eq!(peers.len(), 50);
    assert!(peers
        .iter()
        .all(|p| p.label.is_none() || p.node_id == NodeId::from_bytes([3; 32])));
    shutdown.send(true).unwrap();
    handle.await.unwrap();
    source.shutdown();
    target.shutdown();
}

#[tokio::test]
async fn wire_default_off_returns_explicit_refusal_and_no_records() {
    let mut f = Fixture::new().await;
    f.policy = PrivacyConfig::default();
    let (source, target, shutdown, handle) = worker(&f, false).await;
    source
        .send_frame(f.owner.node_id(), &Frame::PeerExchangeQuoteRequest)
        .await
        .unwrap();
    assert!(
        matches!(response(&source).await, Frame::PeerExchangeRefused { reason } if reason == "peer_exchange_off")
    );
    assert!(f.receiver.list_payments(100).await.unwrap().is_empty());
    shutdown.send(true).unwrap();
    handle.await.unwrap();
    source.shutdown();
    target.shutdown();
}

#[tokio::test]
async fn settled_proof_in_ordinary_message_carrier_cannot_bypass_quote_check() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    let result = crate::msg_handler::whitelist_then_verify(
        &e,
        &konsensus_api::membrane::Membrane::with_capacity(8),
        &f.registry,
        &gate,
        &f.nonces,
        &f.pricing,
        Some(f.receiver.as_ref()),
        0.0,
        Some(f.owner.node_id()),
        konsensus_message::ReachabilityMode::PriceOpen,
        true,
    )
    .await;
    assert!(result.is_err());
    assert!(
        f.redeem(&q, &e).await.is_ok(),
        "wrong carrier must not consume the payment"
    );
}

#[tokio::test]
async fn settlement_must_be_incoming_at_the_quote_issuer() {
    let f = Fixture::new().await;
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    assert!(
        redeem(&q, &e, f.payer.node_id(), &f.owner, &f.nonces, &f.sender)
            .await
            .is_err()
    );
    assert!(f.redeem(&q, &e).await.is_ok());
}

#[tokio::test]
async fn maximum_labels_fit_noise_and_oversized_wire_quotes_are_rejected() {
    let mut f = Fixture::new().await;
    f.policy.shareable_peers = (1..=50).map(|n| NodeId::from_bytes([n; 32])).collect();
    f.policy.share_peer_labels = f.policy.shareable_peers.clone();
    for n in 1..=50 {
        f.registry.write().await.add(PeerEntry {
            node_id: NodeId::from_bytes([n; 32]),
            addr: format!("[2001:db8::{n}]:9735").parse().unwrap(),
            label: Some("L".repeat(256)),
            auto_connect: false,
        });
    }
    let q = f.quote().await.unwrap();
    let e = f.paid(&q).await;
    let bytes = Frame::PeerExchangePaidRequest {
        quote: Box::new(q.clone()),
        envelope: Box::new(e),
    }
    .to_bytes()
    .unwrap();
    assert!(
        bytes.len() < 60_000,
        "canonical request fits Noise record: {}",
        bytes.len()
    );
    assert!(Frame::from_bytes(&bytes).is_ok());
    let mut oversized = q.clone();
    oversized.snapshot = vec![0; 24577];
    assert!(Frame::from_bytes(
        &Frame::PeerExchangeQuote {
            quote: Box::new(oversized)
        }
        .to_bytes()
        .unwrap()
    )
    .is_err());
    let mut oversized = q;
    oversized.bolt11 = "a".repeat(8193);
    assert!(Frame::from_bytes(
        &Frame::PeerExchangeQuote {
            quote: Box::new(oversized)
        }
        .to_bytes()
        .unwrap()
    )
    .is_err());
}
