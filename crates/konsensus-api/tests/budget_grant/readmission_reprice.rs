//! #127 review finding 1: when re-admission resolves through a recovery branch
//! (an admission paid by an earlier call whose proof never landed, or whose
//! dispatch outcome was lost), no quote is fetched in this call. The message
//! price it carries forward (the contact's earlier signed quote) must still fit
//! this call's cap and, for a paired caller, this call's reservation.
use super::*;
use konsensus_api::invoice_refusal;
use konsensus_api::state::{InvoiceRequestOutcome, InvoiceResponseData, InvoiceResponseError};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::{NodeIdentity, UkmEnvelope};
use konsensus_lightning::shared_mock::SharedMockProvider;
use std::time::Instant;

type Requests = Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InvoiceRequestOutcome>>>>;

/// A contact with a live E2EE session. Its connection starts unpaid; it prices
/// admission at 2000 and, in its signed quote, the message at 2000 while the
/// sender's table announces 1000. `flap_on_proof` reconnects as the admission
/// proof is sent, so that proof never lands.
struct Contact {
    peer: NodeId,
    requests: Requests,
    payee: Arc<SharedMockProvider>,
    generation: std::sync::Mutex<Instant>,
    paid: AtomicBool,
    flap_on_proof: AtomicBool,
}

impl Contact {
    fn reconnect(&self) {
        *self.generation.lock().unwrap() = Instant::now();
        self.paid.store(false, Ordering::SeqCst);
    }
}

#[async_trait]
impl MessageTransport for Contact {
    async fn send(&self, _: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if envelope.ciphertext == b"konsensus:admission:v1" {
            self.paid.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn send_on_connection(&self, peer: &NodeId, since: Option<Instant>, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if since != Some(*self.generation.lock().unwrap()) {
            return Err(TransportError::NotConnected("generation changed".into()));
        }
        if envelope.ciphertext == b"konsensus:admission:v1" && self.flap_on_proof.swap(false, Ordering::SeqCst) {
            self.reconnect();
            return Err(TransportError::NotConnected("reconnected while the proof was sent".into()));
        }
        self.send(peer, envelope).await
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        std::future::pending().await
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, _: &NodeId) -> bool {
        true
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer]
    }
    async fn connected_since(&self, _: &NodeId) -> Option<Instant> {
        Some(*self.generation.lock().unwrap())
    }
    async fn admission_paid_on_connection(&self, _: &NodeId) -> bool {
        self.paid.load(Ordering::SeqCst)
    }
    async fn mark_admission_paid(&self, _: &NodeId, since: Instant) {
        if since == *self.generation.lock().unwrap() {
            self.paid.store(true, Ordering::SeqCst);
        }
    }
    async fn send_raw_frame(&self, _: &NodeId, bytes: &[u8]) -> Result<(), TransportError> {
        let konsensus_message::wire::Frame::RequestInvoice { request_id, purpose, amount_msat } =
            konsensus_message::wire::Frame::from_bytes(bytes).unwrap()
        else {
            return Ok(());
        };
        let admission = purpose.starts_with("konsensus:admission");
        let outcome = if !admission && !self.paid.load(Ordering::SeqCst) {
            assert!(invoice_refusal::record(&request_id, &self.peer, invoice_refusal::ADMISSION_REQUIRED));
            Err(InvoiceResponseError { recipient: self.peer, reason: invoice_refusal::ADMISSION_REQUIRED.into() })
        } else {
            let description = if admission { format!("konsensus:{request_id}:message=2000") } else { "konsensus message".into() };
            let invoice = self.payee.create_invoice(if admission { 2000 } else { amount_msat }, &description, 55).await.unwrap();
            Ok(InvoiceResponseData { recipient: self.peer, bolt11: invoice.bolt11, payment_hash: invoice.payment_hash })
        };
        self.requests.lock().await.remove(&request_id).unwrap().send(outcome).unwrap();
        Ok(())
    }
}

/// Pays for real, but loses the response to the next dispatch it is asked
/// for: that payment's outcome is unknown to the caller.
struct LosingWallet {
    inner: Arc<SharedMockProvider>,
    lose_next: AtomicBool,
}

#[async_trait]
impl LightningProvider for LosingWallet {
    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, LightningError> {
        self.inner.create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.pay_invoice(bolt11).await
    }
    async fn pay_invoice_with_fee_limit(&self, bolt11: &str, cap: u64) -> Result<PaymentDetails, LightningError> {
        let paid = self.inner.pay_invoice_with_fee_limit(bolt11, cap).await;
        if self.lose_next.swap(false, Ordering::SeqCst) {
            return Err(LightningError::Connection("response lost".into()));
        }
        paid
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }
    async fn is_available(&self) -> bool {
        true
    }
}

const START_MSAT: u64 = 100_000;

struct Probe {
    fx: Fx,
    contact: Arc<Contact>,
    payer: Arc<SharedMockProvider>,
    wallet: Arc<LosingWallet>,
    token: String,
}

impl Probe {
    async fn new(paired: bool) -> Self {
        let mut fx = fixture().await;
        let path = fx.tmp.path().join("readmit-lightning.db");
        let payer = Arc::new(SharedMockProvider::new(&path, "payer", START_MSAT).unwrap());
        let payee = Arc::new(SharedMockProvider::new(&path, "payee", 0).unwrap());
        let (_, identity) = NodeIdentity::generate().unwrap();
        let peer = *identity.node_id();
        // An existing contact: the E2EE session survives every reconnect.
        let theirs = konsensus_crypto::SessionManager::new(Arc::new(identity));
        let init = fx.state.session_manager.initiate_session(&peer, &theirs.prekey_bundle().await).await.unwrap();
        theirs.accept_session(fx.state.identity.node_id(), &init).await.unwrap();
        let contact = Arc::new(Contact {
            peer,
            requests: fx.state.invoice_requests.clone(),
            payee,
            generation: std::sync::Mutex::new(Instant::now()),
            paid: AtomicBool::new(false),
            flap_on_proof: AtomicBool::new(false),
        });
        let wallet = Arc::new(LosingWallet { inner: payer.clone(), lose_next: AtomicBool::new(false) });
        fx.state = Arc::new(AppState { transport: contact.clone(), lightning: wallet.clone(), ..(*fx.state).clone() });
        fx.peer = peer;
        let token = if paired {
            fx.grant(None, GrantTerms::new(100_000).recipient(&peer.to_hex(), 50_000)).await
        } else {
            konsensus_api::auth::create_token(&fx.state.identity.node_id().to_hex(), &fx.state.jwt_secret, Scope::all()).unwrap()
        };
        Probe { fx, contact, payer, wallet, token }
    }

    async fn compose(&self, text: &str, cap: u64) -> (StatusCode, Value) {
        self.fx.call("POST", "/api/v1/messages/compose", Some(json!({
            "recipient": self.contact.peer.to_hex(), "kind": 0, "plaintext": text,
            "max_total_msat": cap, "operation_id": uuid::Uuid::new_v4().to_string(),
        })), Some(&self.token)).await
    }

    async fn spent(&self) -> u64 {
        START_MSAT - self.payer.get_balance_msat().await.unwrap()
    }
}

/// The earlier call paid admission (2000) and its proof never landed.
async fn admission_paid_proof_lost(p: &Probe) {
    p.contact.flap_on_proof.store(true, Ordering::SeqCst);
    let (status, body) = p.compose("proof lost on a reconnect", 4_000).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert_eq!(p.spent().await, 2_000, "admission only: {body}");
}

#[tokio::test]
async fn recovered_admission_never_pays_the_quoted_message_above_the_owner_cap() {
    let p = Probe::new(false).await;
    admission_paid_proof_lost(&p).await;
    // The announced price (1000) fits 1500; the contact's quote (2000) does not.
    let (status, body) = p.compose("recovered admission", 1_500).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!((body["code"].as_str(), body["reason"].as_str()), (Some("price_cap_exceeded"), Some("readmission_required")), "{body}");
    assert_eq!(p.spent().await, 2_000, "nothing more paid under a 1500 cap");
    // The refused call still re-delivered the paid proof: the connection is
    // admitted, and the next message pays its price only, never admission again.
    let (status, body) = p.compose("after the recovered admission", 2_000).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(p.spent().await, 3_000, "the message once, no second admission");
}

#[tokio::test]
async fn recovered_admission_never_pays_the_quoted_message_above_a_paired_reservation() {
    let p = Probe::new(true).await;
    admission_paid_proof_lost(&p).await;
    let used = p.fx.used();
    // The call reserved the announced 1000; the recovery reserved no increase.
    let (status, body) = p.compose("recovered admission", 4_000).await;
    assert_budget_exceeded(status, &body, "unpriced");
    assert_eq!(p.spent().await, 2_000, "nothing more paid beyond the reservation");
    assert_eq!(p.fx.used(), used, "the grant is not charged for the refusal");
}

#[tokio::test]
async fn resumed_in_flight_admission_never_pays_the_quoted_message_above_the_cap() {
    let p = Probe::new(false).await;
    // The earlier call's admission dispatch outcome was lost: it is resumed,
    // not paid again, by the next call.
    p.wallet.lose_next.store(true, Ordering::SeqCst);
    let (status, body) = p.compose("admission outcome lost", 4_000).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert_eq!(p.spent().await, 2_000);
    let (status, body) = p.compose("resumed admission", 1_500).await;
    assert!(status.is_client_error(), "refused before the message: {status} {body}");
    assert_eq!(p.spent().await, 2_000, "nothing more paid under a 1500 cap");
}
