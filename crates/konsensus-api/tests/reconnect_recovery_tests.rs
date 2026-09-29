//! Reconnect recovery and promotion deadline regressions.
//! No network sockets or real Lightning backend are used.
mod common;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use konsensus_api::{
    auth,
    handlers::messages::create_payment_proof,
    invoice_refusal,
    state::{InvoiceRequestOutcome, InvoiceResponseData, InvoiceResponseError},
};
use konsensus_core::{
    traits::transport::{MessageTransport, TransportError},
    NodeId, NodeIdentity, PaymentProof, Recipient, Signature, UkmEnvelope, UkmEnvelopeBuilder,
};
use konsensus_message::wire::Frame;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, Mutex};
use tower::ServiceExt;

type Requests = Arc<Mutex<HashMap<String, oneshot::Sender<InvoiceRequestOutcome>>>>;

struct RefusingTransport {
    peer: NodeId,
    requests: Requests,
    connected_at: Instant,
    already_paid: bool,
    delay_after_first: Duration,
    stall_write: bool,
    respond_with_invoice: bool,
    last_request: std::sync::Mutex<Option<String>>,
    message_requests: AtomicUsize,
    admission_requests: AtomicUsize,
    stale_proofs: AtomicUsize,
}

#[async_trait]
impl MessageTransport for RefusingTransport {
    async fn send(&self, _: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        // Model a recipient whose replay store already consumed this admission.
        // Sending the replay does not promote the replacement connection.
        if envelope.ciphertext == b"konsensus:admission:v1" {
            self.stale_proofs.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        Err(TransportError::Other(
            "no input in reconnect fixture".into(),
        ))
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        *peer == self.peer
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer]
    }
    async fn connected_since(&self, _: &NodeId) -> Option<Instant> {
        Some(self.connected_at)
    }
    async fn admission_paid_on_connection(&self, _: &NodeId) -> bool {
        self.already_paid
    }
    async fn send_raw_frame(&self, peer: &NodeId, bytes: &[u8]) -> Result<(), TransportError> {
        let Frame::RequestInvoice {
            request_id,
            purpose,
            amount_msat,
        } = Frame::from_bytes(bytes).map_err(|e| TransportError::Other(e.to_string()))?
        else {
            return Ok(());
        };
        *self.last_request.lock().unwrap() = Some(request_id.clone());
        let mut invoice_response = false;
        let admission = purpose.starts_with("konsensus:admission");
        let delay = if admission {
            self.admission_requests.fetch_add(1, Ordering::SeqCst);
            Duration::ZERO
        } else {
            let previous = self.message_requests.fetch_add(1, Ordering::SeqCst);
            if previous > 0 && self.stall_write {
                return std::future::pending().await;
            }
            invoice_response = previous > 0 && self.respond_with_invoice;
            if previous == 0 {
                Duration::ZERO
            } else {
                self.delay_after_first
            }
        };
        let requests = Arc::clone(&self.requests);
        let peer = *peer;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let reason = if admission {
                // A corrected restart path reaches this fresh quote request.
                // Stop here: proving selection does not require paying it.
                "test:fresh_quote_observed"
            } else {
                invoice_refusal::ADMISSION_REQUIRED
            };
            if let Some(sender) = requests.lock().await.remove(&request_id) {
                let outcome = if invoice_response {
                    let bolt11 = common::create_test_bolt11(amount_msat);
                    let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
                    Ok(InvoiceResponseData {
                        recipient: peer,
                        bolt11,
                        payment_hash: invoice.payment_hash().to_string(),
                    })
                } else {
                    assert!(invoice_refusal::record(&request_id, &peer, reason));
                    Err(InvoiceResponseError {
                        recipient: peer,
                        reason: reason.into(),
                    })
                };
                let _ = sender.send(outcome);
            }
        });
        Ok(())
    }
}

async fn sender_with_recovered_journal(age_secs: Option<i64>, connection_paid: bool) {
    let directory = tempfile::tempdir().unwrap();
    let wallet = Arc::new(common::CountingLightning::default());
    let mut state = common::test_state_with_lightning(wallet.clone());
    let (_, recipient_identity) = NodeIdentity::generate().unwrap();
    let peer = *recipient_identity.node_id(); // Unique: process-wide ledger has no record.
    let recipient_sessions = konsensus_crypto::SessionManager::new(Arc::new(recipient_identity));
    state
        .session_manager
        .initiate_session(&peer, &recipient_sessions.prekey_bundle().await)
        .await
        .unwrap(); // Same state as a session restored at node startup.
    assert!(state.session_manager.has_session(&peer).await);

    let preimage = [43u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let mut old_proof = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *state.identity.node_id(),
        Recipient::Node(peer),
        b"konsensus:admission:v1".to_vec(),
        PaymentProof::new(hash, preimage, 2000),
    )
    .build();
    old_proof.signature =
        Signature::from_ed25519(&state.identity.sign(&old_proof.signable_bytes()));
    let journal = directory.path().join("admission-attempts");
    std::fs::create_dir(&journal).unwrap();
    std::fs::write(
        journal.join(peer.to_hex()),
        serde_json::to_vec(&serde_json::json!({
            "payment_hash": hex::encode(hash), "amount_msat": 2000,
            "quote": [konsensus_core::kind::KIND_CHAT, 2000], "envelope": old_proof,
            "settled_at_unix": age_secs.map(|age| (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - age) as u64),
            "original_reservation": null, "message_may_have_dispatched": true
        }))
        .unwrap(),
    )
    .unwrap();

    let transport = Arc::new(RefusingTransport {
        peer,
        requests: Arc::clone(&state.invoice_requests),
        connected_at: Instant::now(),
        already_paid: connection_paid,
        delay_after_first: Duration::ZERO,
        stall_write: false,
        respond_with_invoice: false,
        last_request: Default::default(),
        message_requests: AtomicUsize::new(0),
        admission_requests: AtomicUsize::new(0),
        stale_proofs: AtomicUsize::new(0),
    });
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.data_dir = Some(directory.path().to_path_buf());
    mutable.transport = transport.clone();
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();
    let started = tokio::time::Instant::now();
    let response = common::test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "recipient": peer.to_hex(), "kind": konsensus_core::kind::KIND_CHAT,
                        "plaintext": "first message after sender restart"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let message_requests = transport.message_requests.load(Ordering::SeqCst);
    let fresh_quotes = transport.admission_requests.load(Ordering::SeqCst);
    let stale = transport.stale_proofs.load(Ordering::SeqCst);
    eprintln!("restart evidence: status={status}, elapsed={:?}, message_requests={message_requests}, fresh_quotes={fresh_quotes}, stale_proofs={stale}, body={}", started.elapsed(), String::from_utf8_lossy(&body));
    assert_eq!(wallet.money(), 0, "fixture must never move money");
    assert_eq!(stale, 0, "a consumed proof must never be replayed");
    if connection_paid {
        assert_eq!(
            fresh_quotes, 0,
            "current connection payment guard must win over recovered evidence"
        );
        assert!(journal.join(peer.to_hex()).exists());
    } else {
        assert_eq!(
            fresh_quotes, 1,
            "new unpaid connection must request fresh admission after restart"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn restarted_sender_requests_fresh_admission_instead_of_replaying_consumed_proof() {
    sender_with_recovered_journal(Some(5), false).await;
}

#[tokio::test(start_paused = true)]
async fn same_second_restart_does_not_treat_recovered_payment_as_current() {
    sender_with_recovered_journal(Some(0), false).await;
}

#[tokio::test(start_paused = true)]
async fn legacy_journal_without_timestamp_does_not_cover_replacement_connection() {
    sender_with_recovered_journal(None, false).await;
}

#[tokio::test(start_paused = true)]
async fn backward_wall_clock_change_does_not_cover_replacement_connection() {
    sender_with_recovered_journal(Some(-60), false).await;
}

#[tokio::test(start_paused = true)]
async fn current_connection_payment_guard_wins_over_recovered_journal() {
    sender_with_recovered_journal(None, true).await;
}

#[tokio::test(start_paused = true)]
async fn promotion_wait_has_a_real_twenty_second_deadline() {
    let wallet = Arc::new(common::CountingLightning::default());
    let mut state = common::test_state_with_lightning(wallet.clone());
    let (_, recipient_identity) = NodeIdentity::generate().unwrap();
    let peer = *recipient_identity.node_id();
    let transport = Arc::new(RefusingTransport {
        peer,
        requests: Arc::clone(&state.invoice_requests),
        connected_at: Instant::now(),
        already_paid: true,
        delay_after_first: Duration::from_secs(29),
        stall_write: false,
        respond_with_invoice: false,
        last_request: Default::default(),
        message_requests: AtomicUsize::new(0),
        admission_requests: AtomicUsize::new(0),
        stale_proofs: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    let started = tokio::time::Instant::now();
    let result = create_payment_proof(&state, 2000, &peer).await;
    let elapsed = started.elapsed();
    let requests = transport.message_requests.load(Ordering::SeqCst);
    eprintln!("deadline evidence: elapsed={elapsed:?}, requests={requests}, result={result:?}");
    assert!(result.is_err());
    assert!(state.invoice_requests.lock().await.is_empty());
    let last_request = transport.last_request.lock().unwrap().clone().unwrap();
    assert!(!invoice_refusal::record(
        &last_request,
        &peer,
        invoice_refusal::ADMISSION_REQUIRED
    ));
    assert_eq!(wallet.money(), 0);
    assert_eq!(
        transport.admission_requests.load(Ordering::SeqCst),
        0,
        "same connection cannot buy admission again"
    );
    assert!(
        elapsed <= Duration::from_secs(20),
        "20s promotion budget excludes invoice latency: elapsed={elapsed:?}, requests={requests}"
    );
}

fn connected_state(
    wallet: Arc<dyn konsensus_core::traits::lightning::LightningProvider>,
    configure: impl FnOnce(&mut RefusingTransport),
) -> (Arc<konsensus_api::AppState>, Arc<RefusingTransport>) {
    let mut state = common::test_state_with_lightning(wallet);
    let (_, identity) = NodeIdentity::generate().unwrap();
    let mut transport = RefusingTransport {
        peer: *identity.node_id(),
        requests: Arc::clone(&state.invoice_requests),
        connected_at: Instant::now(),
        already_paid: true,
        delay_after_first: Duration::ZERO,
        stall_write: false,
        respond_with_invoice: false,
        last_request: Default::default(),
        message_requests: AtomicUsize::new(0),
        admission_requests: AtomicUsize::new(0),
        stale_proofs: AtomicUsize::new(0),
    };
    configure(&mut transport);
    let transport = Arc::new(transport);
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    (state, transport)
}

#[tokio::test(start_paused = true)]
async fn promotion_deadline_includes_a_stalled_request_write() {
    let wallet = Arc::new(common::CountingLightning::default());
    let (state, transport) = connected_state(wallet.clone(), |t| t.stall_write = true);
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(25),
        create_payment_proof(&state, 2000, &transport.peer),
    )
    .await
    .expect("promotion deadline must cancel the prepayment request write");
    assert!(result.is_err());
    assert_eq!(started.elapsed(), Duration::from_secs(20));
    assert!(state.invoice_requests.lock().await.is_empty());
    let last = transport.last_request.lock().unwrap().clone().unwrap();
    assert!(!invoice_refusal::record(
        &last,
        &transport.peer,
        invoice_refusal::ADMISSION_REQUIRED
    ));
    assert_eq!(wallet.money(), 0);
}

#[tokio::test(start_paused = true)]
async fn successive_refusals_share_one_promotion_deadline() {
    let wallet = Arc::new(common::CountingLightning::default());
    let (state, transport) = connected_state(wallet.clone(), |t| {
        t.delay_after_first = Duration::from_secs(5)
    });
    let started = tokio::time::Instant::now();
    assert!(create_payment_proof(&state, 2000, &transport.peer)
        .await
        .is_err());
    assert_eq!(started.elapsed(), Duration::from_secs(20));
    assert!(transport.message_requests.load(Ordering::SeqCst) > 2);
    assert_eq!(transport.admission_requests.load(Ordering::SeqCst), 0);
    assert!(state.invoice_requests.lock().await.is_empty());
    assert_eq!(wallet.money(), 0);
}

#[tokio::test(start_paused = true)]
async fn restart_keeps_an_unknown_payment_attempt_without_requesting_another_invoice() {
    let wallet = Arc::new(common::CountingLightning::default());
    let (mut state, transport) = connected_state(wallet.clone(), |t| t.already_paid = false);
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("admission-attempts");
    std::fs::create_dir(&journal).unwrap();
    let path = journal.join(transport.peer.to_hex());
    let attempt = serde_json::json!({
        "payment_hash": "43".repeat(32), "amount_msat": 2000,
        "quote": [konsensus_core::kind::KIND_CHAT, 2000], "envelope": null,
        "settled_at_unix": null, "original_reservation": null,
        "message_may_have_dispatched": false
    });
    std::fs::write(&path, serde_json::to_vec(&attempt).unwrap()).unwrap();
    Arc::get_mut(&mut state).unwrap().data_dir = Some(directory.path().to_path_buf());
    assert!(create_payment_proof(&state, 2000, &transport.peer)
        .await
        .is_err());
    assert_eq!(transport.admission_requests.load(Ordering::SeqCst), 0);
    assert_eq!(transport.stale_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.money(), 0);
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(retained, attempt);
}

struct SlowSettlement {
    payments: AtomicUsize,
}

use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
#[async_trait]
impl LightningProvider for SlowSettlement {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.pay_invoice(invoice).await
    }

    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, _cap: u64) -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError> {
        self.keysend(dest, amount, memo).await
    }

    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        common::StubLightning
            .create_invoice(amount, description, expiry)
            .await
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.payments.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(30)).await;
        common::StubLightning.pay_invoice(bolt11).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        common::StubLightning.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(100_000)
    }
    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test(start_paused = true)]
async fn promotion_deadline_does_not_cancel_a_dispatched_payment() {
    let wallet = Arc::new(SlowSettlement {
        payments: AtomicUsize::new(0),
    });
    let (state, transport) = connected_state(wallet.clone(), |t| {
        t.delay_after_first = Duration::from_secs(19);
        t.respond_with_invoice = true;
    });
    let started = tokio::time::Instant::now();
    let proof = create_payment_proof(&state, 2000, &transport.peer)
        .await
        .unwrap();
    assert_eq!(proof.2, 2000);
    assert_eq!(wallet.payments.load(Ordering::SeqCst), 1);
    assert_eq!(started.elapsed(), Duration::from_secs(49));
    assert!(state.invoice_requests.lock().await.is_empty());
    assert_eq!(transport.admission_requests.load(Ordering::SeqCst), 0);
}

/// The actual first-contact resend branch must renew the durable admission
/// wrapper inside its 15-minute paid-proof TTL, without paying another invoice.
#[tokio::test]
async fn fourteen_minute_admission_resend_renews_same_paid_envelope() {
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_storage::{SqliteStorage, Storage, PaidAcceptance};
    let dir = tempfile::tempdir().unwrap();
    let sender_wallet = Arc::new(common::CountingLightning::default());
    let recipient_wallet = konsensus_lightning::MockLightningProvider::new();
    let (_, recipient) = NodeIdentity::generate().unwrap();
    let peer = *recipient.node_id();
    let hash = recipient_wallet.inject_inbound_keysend(2000, None).await;
    let details = recipient_wallet.get_payment_status(&hash).await.unwrap();
    let mut state = (*common::test_state_with_lightning(sender_wallet.clone())).clone();
    state.data_dir = Some(dir.path().to_path_buf());
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    state.storage = db.clone();
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()));
    state.transport = transport.clone();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut old = UkmEnvelopeBuilder::new(konsensus_core::kind::KIND_CHAT,
        *state.identity.node_id(), Recipient::Node(peer), b"konsensus:admission:v1".to_vec(),
        PaymentProof::new(hex::decode(&hash).unwrap().try_into().unwrap(),
            hex::decode(details.preimage.unwrap()).unwrap().try_into().unwrap(), 2000))
        .timestamp(now.as_millis() as u64 - 840_000).build();
    old.signature = Signature::from_ed25519(&state.identity.sign(&old.signable_bytes()));
    let journal = dir.path().join("admission-attempts"); std::fs::create_dir(&journal).unwrap();
    std::fs::write(journal.join(peer.to_hex()), serde_json::to_vec(&serde_json::json!({
        "payment_hash": hash, "amount_msat": 2000, "quote": [0, 2000], "envelope": old,
        "settled_at_unix": now.as_secs() - 840, "original_reservation": null,
        "message_may_have_dispatched": false
    })).unwrap()).unwrap();
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, auth::Scope::all()).unwrap();
    let app = common::test_router(Arc::new(state));
    let response = app.oneshot(Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"after admission"}).to_string())).unwrap()).await.unwrap();
    // No X3DH peer is running, so compose eventually times out after resending.
    assert!(response.status().is_server_error());
    assert_eq!(sender_wallet.money(), 0);
    let renewed = {
        let sent = transport.sent_envelopes.lock().unwrap();
        assert_eq!(sent.len(), 1);
        sent[0].1.clone()
    };
    assert!(renewed.timestamp > old.timestamp);
    let mut expected = old.clone(); expected.timestamp = renewed.timestamp; expected.signature = renewed.signature;
    assert_eq!(renewed, expected);
    assert!(db.get_message(&old.id).await.unwrap().is_none(), "admission must not appear as outgoing chat");
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 0);
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(journal.join(peer.to_hex())).unwrap()).unwrap();
    assert_eq!(serde_json::from_value::<UkmEnvelope>(saved["envelope"].clone()).unwrap(), renewed);
    let recipient_db = SqliteStorage::in_memory().await.unwrap();
    let gate = konsensus_core::gate::PaymentGate::with_config(konsensus_core::gate::GateConfig {
        verify_lightning_settlement: true, ..Default::default()
    });
    let pricing = konsensus_pricing::StaticPricingEngine::new(Default::default());
    gate.validate_paid_envelope(&renewed, &pricing, None, Some(&recipient_wallet), 0.0, Some(&peer)).await.unwrap();
    assert_eq!(recipient_db.accept_paid_envelope(&renewed).await.unwrap(), PaidAcceptance::Accepted);
    assert_eq!(recipient_db.accept_paid_envelope(&renewed).await.unwrap(), PaidAcceptance::AlreadyAccepted);
}

/// Peers that always refuse the message invoice with `admission_required`
/// (reconnect starts unpaid). Admission quote requests are counted so capped
/// room/file paths can prove they refuse before asking.
struct AdmissionRequiredPeers {
    peers: Vec<NodeId>,
    requests: Requests,
    connected_at: Instant,
    message_requests: AtomicUsize,
    admission_requests: AtomicUsize,
}

#[async_trait]
impl MessageTransport for AdmissionRequiredPeers {
    async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> {
        Ok(())
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        Err(TransportError::Other("no input".into()))
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.peers.contains(peer)
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.clone()
    }
    async fn connected_since(&self, _: &NodeId) -> Option<Instant> {
        Some(self.connected_at)
    }
    async fn admission_paid_on_connection(&self, _: &NodeId) -> bool {
        false
    }
    async fn send_raw_frame(&self, peer: &NodeId, bytes: &[u8]) -> Result<(), TransportError> {
        let Frame::RequestInvoice {
            request_id,
            purpose,
            ..
        } = Frame::from_bytes(bytes).map_err(|e| TransportError::Other(e.to_string()))?
        else {
            return Ok(());
        };
        let admission = purpose.starts_with("konsensus:admission");
        if admission {
            self.admission_requests.fetch_add(1, Ordering::SeqCst);
        } else {
            self.message_requests.fetch_add(1, Ordering::SeqCst);
        }
        let requests = Arc::clone(&self.requests);
        let peer = *peer;
        let reason = if admission {
            "test:should_not_request_admission"
        } else {
            invoice_refusal::ADMISSION_REQUIRED
        };
        tokio::spawn(async move {
            if let Some(sender) = requests.lock().await.remove(&request_id) {
                assert!(invoice_refusal::record(&request_id, &peer, reason));
                let _ = sender.send(Err(InvoiceResponseError {
                    recipient: peer,
                    reason: reason.into(),
                }));
            }
        });
        Ok(())
    }
}

async fn post_json(
    state: &Arc<konsensus_api::AppState>,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    let response = common::test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100_000).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::json!({"raw": String::from_utf8_lossy(&bytes)})
        }),
    )
}

/// Capped room fan-out with reconnecting members must refuse re-admission
/// before any quote and pay nothing (pre-#111 / CoS: no aggregate-cap handoff).
#[tokio::test]
async fn capped_room_reconnect_refuses_readmission_and_pays_nothing() {
    let wallet = Arc::new(common::CountingLightning::default());
    let mut state = common::test_state_with_lightning(wallet.clone());
    let first = common::setup_e2ee_session(&state.session_manager).await;
    let second = common::setup_e2ee_session_with_mnemonic(
        &state.session_manager,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .await;
    let transport = Arc::new(AdmissionRequiredPeers {
        peers: vec![first, second],
        requests: Arc::clone(&state.invoice_requests),
        connected_at: Instant::now(),
        message_requests: AtomicUsize::new(0),
        admission_requests: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();

    let (_, room) = post_json(&state, &token, "/api/v1/rooms", serde_json::json!({"name": "cap"})).await;
    let id = room["id"].as_str().unwrap();
    for peer in [first, second] {
        assert_eq!(
            post_json(
                &state,
                &token,
                &format!("/api/v1/rooms/{id}/members"),
                serde_json::json!({"node_id": peer.to_hex()}),
            )
            .await
            .0,
            axum::http::StatusCode::OK
        );
    }

    // Messages alone fit (2 × 1000 msat payable); re-admission must still refuse.
    let (status, body) = post_json(
        &state,
        &token,
        "/api/v1/messages/compose",
        serde_json::json!({
            "recipient": id,
            "is_room": true,
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": "room after reconnect",
            "max_routing_fee_msat": 0,
            "max_total_msat": 2000,
            "max_recipient_msat": {
                first.to_hex(): 1000,
                second.to_hex(): 1000,
            }
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let rows = body["member_outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{body}");
    assert!(
        rows.iter().all(|r| r["status"] == "refused" && r["amount_msat"] == 0),
        "{body}"
    );
    assert_eq!(body["amount_msat"], 0, "{body}");
    assert!(body["readmission_msat"].is_null() || body["readmission_msat"] == 0, "{body}");
    assert_eq!(wallet.money(), 0, "capped room must pay nothing on reconnect");
    assert_eq!(
        transport.admission_requests.load(Ordering::SeqCst),
        0,
        "must refuse before any admission quote"
    );
    assert!(
        transport.message_requests.load(Ordering::SeqCst) >= 1,
        "message invoice must force the admission_required path"
    );
}

/// Capped file send that needs re-admission must refuse before pay and before
/// any chat-priced admission quote (CoS: non-chat keeps pre-#111 refusal).
#[tokio::test]
async fn capped_file_reconnect_refuses_readmission_before_pay() {
    let wallet = Arc::new(common::CountingLightning::default());
    let mut state = common::test_state_with_lightning(wallet.clone());
    let peer = common::setup_e2ee_session(&state.session_manager).await;
    let transport = Arc::new(AdmissionRequiredPeers {
        peers: vec![peer],
        requests: Arc::clone(&state.invoice_requests),
        connected_at: Instant::now(),
        message_requests: AtomicUsize::new(0),
        admission_requests: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        auth::Scope::all(),
    )
    .unwrap();

    let (status, file) = post_json(
        &state,
        &token,
        "/api/v1/files",
        serde_json::json!({"filename": "hi.txt", "mime_type": "text/plain", "data_b64": "aGk="}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{file}");
    let path = format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap());
    // File principal alone fits; re-admission must still refuse before any quote.
    let (status, body) = post_json(
        &state,
        &token,
        &path,
        serde_json::json!({
            "recipient": peer.to_hex(),
            "max_routing_fee_msat": 0,
            "max_total_msat": 1000
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded", "{body}");
    assert_eq!(wallet.money(), 0, "capped file must pay nothing on reconnect");
    assert_eq!(
        transport.admission_requests.load(Ordering::SeqCst),
        0,
        "must refuse before any admission quote"
    );
    assert_eq!(
        transport.message_requests.load(Ordering::SeqCst),
        1,
        "file invoice must force the admission_required path"
    );
}
