//! G1 × F1: a paired client pays a first contact only with the owner's
//! one-time confirmation for that contact (a first-contact grant), and the
//! whole first contact — admission plus the first message — is debited once.
//!
//! A real pairing and owner-granted budget (the G1 fixture), F1's shared mock
//! Lightning (recipient-bound settlement) and a stranger that answers invoice
//! requests with a signed quote, as in `first_contact_tests.rs`.

use super::*;
use konsensus_api::state::InvoiceResponseData;
use konsensus_lightning::shared_mock::SharedMockProvider;

struct Stranger {
    fx: Fx,
    peer: NodeId,
    sender_wallet: Arc<SharedMockProvider>,
    invoices: Arc<AtomicUsize>,
    handshake: tokio::task::JoinHandle<()>,
    _ledger: tempfile::TempDir,
}

impl Drop for Stranger {
    fn drop(&mut self) {
        self.handshake.abort();
    }
}

/// A connected `price_open` stranger pricing admission at 2,000 msat and
/// signing `message_msat` as the first message's price. Once its wallet has
/// been paid, it establishes the E2EE session (promotion), as a target does.
async fn stranger(message_msat: u64) -> Stranger {
    stranger_with(message_msat, true).await
}

/// `establish: false` — the stranger takes the admission payment but never
/// opens a session (the send times out after paying admission).
async fn stranger_with(message_msat: u64, establish: bool) -> Stranger {
    let mut fx = fixture().await;
    let ledger = tempfile::tempdir().unwrap();
    let path = ledger.path().join("ledger.db");
    let a = Arc::new(SharedMockProvider::new(&path, "a", 100_000).unwrap());
    let b = Arc::new(SharedMockProvider::new(&path, "b", 0).unwrap());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let invoices = Arc::new(AtomicUsize::new(0));
    let (count, target) = (Arc::clone(&invoices), Arc::clone(&b));
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |request_id, _hint| {
            count.fetch_add(1, Ordering::SeqCst);
            let inv = futures::executor::block_on(target.create_invoice(
                2000,
                &format!("konsensus:{request_id}:message={message_msat}"),
                55,
            ))
            .unwrap();
            Some(InvoiceResponseData {
                recipient: peer,
                bolt11: inv.bolt11,
                payment_hash: inv.payment_hash,
            })
        });
    fx.state = Arc::new(AppState {
        lightning: a.clone(),
        transport: Arc::new(transport),
        ..(*fx.state).clone()
    });
    let sessions = fx.state.session_manager.clone();
    let paid = Arc::clone(&b);
    let handshake = tokio::spawn(async move {
        loop {
            if establish && paid.get_balance_msat().await.unwrap() > 0 {
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
    Stranger {
        fx,
        peer,
        sender_wallet: a,
        invoices,
        handshake,
        _ledger: ledger,
    }
}

impl Stranger {
    async fn spent(&self) -> u64 {
        100_000 - self.sender_wallet.get_balance_msat().await.unwrap()
    }

    async fn confirm(&self, _token: &str, recipient: &NodeId, max_total_msat: u64) -> (StatusCode, Value) {
        self.fx.owner_confirm(&recipient.to_hex(), max_total_msat).await
    }

    async fn send(&self, token: &str, cap: Option<u64>) -> (StatusCode, Value) {
        let mut body = json!({"recipient": self.peer.to_hex(), "kind": 0, "plaintext": "hello stranger"});
        if let Some(cap) = cap {
            body["max_total_msat"] = json!(cap);
        }
        self.fx
            .call("POST", "/api/v1/messages/compose", Some(body), Some(token))
            .await
    }
}

#[tokio::test(start_paused = true)]
async fn confirmed_first_contact_pays_both_legs_and_debits_the_budget_once() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, grant) = s.confirm(&token, &s.peer, 4000).await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    assert_eq!(grant["recipient"], s.peer.to_hex());
    assert_eq!(grant["max_total_msat"], 4000);

    let (status, body) = s.send(&token, Some(4000)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 4000, "admission + message under one cap");
    assert_eq!(s.spent().await, 4000);
    assert_eq!(s.fx.used(), 4000, "one debit, resolved once to what settled");

    // Single use: the confirmation is gone after the send.
    assert_eq!(
        s.fx.service.take_first_contact(&s.fx.client_id, 1, &s.peer.to_hex()),
        None
    );
    // The next confirmation must fit what is left of the budget (6,000 msat).
    let other = NodeId::from_hex(&"cd".repeat(32)).unwrap();
    let (status, body) = s.confirm(&token, &other, 6_001).await;
    assert_budget_exceeded(status, &body, "total");
    let (status, _) = s.confirm(&token, &other, 6_000).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn no_confirmation_means_no_invoice_and_no_payment() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, body) = s.send(&token, Some(4000)).await;
    assert_budget_exceeded(status, &body, "first_contact");
    assert_eq!(s.invoices.load(Ordering::SeqCst), 0, "nothing asked of the stranger");
    assert_eq!(s.spent().await, 0);
    assert_eq!(s.fx.used(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_confirmation_is_for_exactly_one_contact() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let other = NodeId::from_hex(&"cd".repeat(32)).unwrap();
    let (status, _) = s.confirm(&token, &other, 4000).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = s.send(&token, Some(4000)).await;
    assert_budget_exceeded(status, &body, "first_contact");
    assert_eq!(s.invoices.load(Ordering::SeqCst), 0);
    assert_eq!(s.spent().await, 0);
}

#[tokio::test(start_paused = true)]
async fn the_confirmed_amount_caps_the_whole_first_contact() {
    // The stranger asks 2,000 + 2,000; the owner confirmed only 3,999, and
    // the request itself names no cap: the confirmation is the cap.
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    s.confirm(&token, &s.peer, 3999).await;
    let (status, body) = s.send(&token, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded");
    assert_eq!(s.spent().await, 0, "refused before the admission payment");
    assert_eq!(s.fx.used(), 0, "the reservation is released");
}

#[tokio::test(start_paused = true)]
async fn a_confirmation_must_fit_the_budget_grant() {
    let s = stranger(2000).await;
    let token = s
        .fx
        .grant(None, GrantTerms::new(3_000).per_call(2_500))
        .await;
    let (status, body) = s.confirm(&token, &s.peer, 2_600).await;
    assert_budget_exceeded(status, &body, "per_call");
    let token = s.fx.grant(None, GrantTerms::new(1_000_000)).await;
    let (status, body) = s.confirm(&token, &s.peer, 100_001).await;
    assert_budget_exceeded(status, &body, "first_contact");
    let (status, body) = s.fx.owner_confirm("not-a-node", 4000).await;
    assert_budget_exceeded(status, &body, "first_contact");
}

#[tokio::test(start_paused = true)]
async fn no_budget_grant_means_no_confirmation_and_no_quote() {
    let s = stranger(2000).await;
    let read = s.fx.token().await;
    let (status, _) = s.fx.call("POST", "/api/v1/pair/first-contact-grant",
        Some(json!({"recipient": s.peer.to_hex(), "max_total_msat": 4000})), Some(&read)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a paired client cannot mint owner approval");
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    s.fx.service.revoke_grants(Some(&s.fx.client_id)).unwrap();
    let (status, body) = s.confirm(&token, &s.peer, 4000).await;
    assert_budget_exceeded(status, &body, "no_grant");
    assert_eq!(s.invoices.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn revoking_the_budget_voids_an_unused_confirmation() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, _) = s.confirm(&token, &s.peer, 4000).await;
    assert_eq!(status, StatusCode::OK);
    s.fx.service.revoke_grants(Some(&s.fx.client_id)).unwrap();
    assert_eq!(
        s.fx.service.take_first_contact(&s.fx.client_id, 1, &s.peer.to_hex()),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn the_door_quote_is_the_invoice_the_send_pays() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, quote) = s
        .fx
        .call(
            "POST",
            "/api/v1/messages/first-contact/quote",
            Some(json!({"recipient": s.peer.to_hex()})),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!(quote["admission_msat"], 2000);
    assert_eq!(quote["message_msat"], 2000);
    assert_eq!(quote["total_msat"], 4000);
    assert_eq!(s.spent().await, 0, "a quote pays nothing");
    assert_eq!(s.fx.used(), 0, "a quote reserves nothing");
    assert_eq!(s.invoices.load(Ordering::SeqCst), 1);

    s.confirm(&token, &s.peer, 4000).await;
    let (status, body) = s.send(&token, Some(4000)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(s.spent().await, 4000);
    // One admission invoice (the quoted one) plus one message invoice: the
    // confirmed send never asked the stranger for a second admission quote.
    assert_eq!(s.invoices.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn a_quote_needs_a_live_budget_grant() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    s.fx.service.revoke_grants(Some(&s.fx.client_id)).unwrap();
    let (status, _) = s
        .fx
        .call(
            "POST",
            "/api/v1/messages/first-contact/quote",
            Some(json!({"recipient": s.peer.to_hex()})),
            Some(&token),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(s.invoices.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn admission_paid_then_no_session_keeps_exactly_the_admission_charged() {
    let s = stranger_with(2000, false).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    s.confirm(&token, &s.peer, 4000).await;
    let (status, body) = s.send(&token, Some(4000)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["code"], "payment_settled_send_incomplete", "{body}");
    assert_eq!(body["amount_msat"], 2000);
    assert_eq!(s.spent().await, 2000, "only the admission left the wallet");
    assert_eq!(s.fx.used(), 2000, "resolved once: the paid admission stays charged, the rest is released");
}

// Regressions for authorization and signed quote boundaries.
#[tokio::test(start_paused = true)]
async fn regression_cached_chat_quote_does_not_pay_non_chat_first_contact() {
    let uncached = stranger(2000).await;
    let uncached_token = uncached.fx.grant(None, GrantTerms::new(10_000)).await;
    assert_eq!(uncached.confirm(&uncached_token, &uncached.peer, 4000).await.0, StatusCode::OK);
    let (status, body) = uncached.fx.call("POST", "/api/v1/messages/compose",
        Some(json!({"recipient": uncached.peer.to_hex(), "kind": 200, "plaintext": "non-chat", "max_total_msat": 4000})),
        Some(&uncached_token)).await;
    println!("uncached control: {status} {body}; paid={}", uncached.spent().await);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(uncached.spent().await, 0);
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, quote) = s.fx.call("POST", "/api/v1/messages/first-contact/quote",
        Some(json!({"recipient": s.peer.to_hex()})), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!(s.confirm(&token, &s.peer, 4000).await.0, StatusCode::OK);
    let (status, body) = s.fx.call("POST", "/api/v1/messages/compose",
        Some(json!({"recipient": s.peer.to_hex(), "kind": 200, "plaintext": "non-chat", "max_total_msat": 4000})),
        Some(&token)).await;
    println!("non-chat response: {status} {body}; paid={}", s.spent().await);
    assert_eq!(s.spent().await, 0, "chat-only quote must not authorize a file-kind first contact");
}

#[tokio::test(start_paused = true)]
async fn regression_advertised_expiry_does_not_outlive_signed_invoice() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, quote) = s.fx.call("POST", "/api/v1/messages/first-contact/quote",
        Some(json!({"recipient": s.peer.to_hex()})), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // This fixture issues a BOLT11 with a signed 55-second expiry.
    let advertised = quote["expires_at"].as_u64().unwrap();
    println!("advertised={advertised}; latest possible signed expiry={}", now + 55);
    assert!(advertised <= now + 55, "advertised quote validity exceeds signed invoice expiry");
}

#[tokio::test(start_paused = true)]
async fn regression_paired_budget_token_cannot_self_confirm_stranger() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    // All remaining operations are ordinary paired-client HTTP requests.
    // No owner terminal/control operation or owner proof is supplied.
    let (status, confirmation) = s.fx.call("POST", "/api/v1/pair/first-contact-grant", Some(json!({
        "client_id": s.fx.client_id,
        "grant_op_id": s.fx.service.grant_view_for(&s.fx.client_id).unwrap().op_id,
        "recipient": s.peer.to_hex(), "max_total_msat": 4000,
    })), Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    println!("paired self-confirmation: {status} {confirmation}");
    let (status, body) = s.send(&token, Some(4000)).await;
    println!("paired send: {status} {body}; paid={}", s.spent().await);
    assert_eq!(s.spent().await, 0, "paired program must not replace owner confirmation");
}

#[tokio::test]
async fn regression_consumed_confirmation_cannot_move_to_replacement_grant() {
    let s = stranger(2000).await;
    let token = s.fx.grant(None, GrantTerms::new(10_000)).await;
    assert_eq!(s.confirm(&token, &s.peer, 4000).await.0, StatusCode::OK);
    let approval = s.fx.service.take_first_contact(&s.fx.client_id, 1, &s.peer.to_hex()).unwrap();
    let original = s.fx.service.grant_view_for(&s.fx.client_id).unwrap().op_id;
    // Exact interleaving: consumption under A, replacement by B, then debit.
    s.fx.grant(None, GrantTerms::new(10_000)).await;
    assert_ne!(s.fx.service.grant_view_for(&s.fx.client_id).unwrap().op_id, original);
    let debit = s.fx.service.reserve_first_contact(approval, None);
    assert_eq!(debit, Err(BudgetRefusal::NoGrant));
    assert_eq!(s.fx.used(), 0);
    assert_eq!(s.spent().await, 0);
}
