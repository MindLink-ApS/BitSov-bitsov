//! Browse end to end (docs/protocol/BROWSE.md): two real nodes over loopback
//! Noise and the shared mock Lightning ledger, the reader driven through its
//! real `POST /api/v1/browse/fetch` route. Each porch read pays the owner its
//! web-content price (1 sat) once; the reply is bound to that payment, moves no
//! money and promotes nothing.

use super::*;

use konsensus_core::front_door::{FrontDoorCard, FrontDoorFields, FrontDoorPrices, FrontDoorProfile, ProfileKind};
use konsensus_core::payloads::content::PORCH_CARD_PATH;

const PAGE_MSAT: u64 = 1_000;

/// Ledger timestamps are whole seconds, so payments within one second have no
/// stable order; compare what was paid, not when.
fn sorted(mut msat: Vec<u64>) -> Vec<u64> {
    msat.sort_unstable();
    msat
}

fn card(owner: &Node, seq: u64) -> FrontDoorCard {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    FrontDoorCard::issue(
        &owner.identity,
        FrontDoorFields {
            network: "regtest".into(),
            endpoint: owner.addr(),
            seq,
            issued_at: now,
            prices: FrontDoorPrices { admission_msat: CHAT_MSAT, message_msat: CHAT_MSAT, page_msat: PAGE_MSAT, price_epoch: 0 },
            profile: FrontDoorProfile {
                kind: ProfileKind::Person,
                display_name: format!("Maya v{seq}"),
                tagline: String::new(),
                about: String::new(),
                avatar: None,
            },
            cv: None,
            media: vec![],
            site: None,
            links: vec![],
        },
    )
    .unwrap()
}

impl Node {
    async fn browse(&self, owner: &NodeId, path: &str) -> (StatusCode, serde_json::Value) {
        self.post("/api/v1/browse/fetch", serde_json::json!({"node_id": owner.to_hex(), "path": path})).await
    }

    async fn held_cards(&self) -> serde_json::Value {
        let request = Request::builder()
            .uri("/api/v1/browse/cards")
            .header("authorization", &self.auth)
            .body(Body::empty())
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn received_in(&self) -> Vec<u64> {
        let mut got: Vec<_> = self.wallet.list_payments(100).await.unwrap().into_iter()
            .filter(|p| p.direction == PaymentDirection::Incoming)
            .map(|p| (p.timestamp, p.amount_msat))
            .collect();
        got.sort();
        got.into_iter().map(|(_, msat)| msat).collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn porch_read_pays_once_and_returns_the_verified_card() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let owner = net.payee.id;
    // Knock: the paid first contact that gives the reader a session.
    let (status, body) = net.payer.compose(&owner, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    let mut paid = vec![CHAT_MSAT, CHAT_MSAT];
    assert_eq!(sorted(net.payer.paid_out().await), sorted(paid.clone()));

    // The owner publishes a card and has a one-page site.
    *net.payee.front_door.card.lock().await = Some(card(&net.payee, 1));
    std::fs::write(net.payee.data_dir.join("pages/index.md"), "# Maya\n\nHello from the porch.").unwrap();

    let (status, body) = net.payer.browse(&owner, PORCH_CARD_PATH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!((body["status"].as_str(), body["amount_msat"].as_u64()), (Some("Ok"), Some(PAGE_MSAT)), "{body}");
    assert_eq!(body["card"]["card"]["node_id"], owner.to_hex());
    assert_eq!(body["card"]["card"]["seq"], 1);
    assert_eq!(body["card"]["fresh"], true);
    assert!(body["card"]["stale"].is_null(), "{body}");
    paid.push(PAGE_MSAT);
    assert_eq!(sorted(net.payer.paid_out().await), sorted(paid.clone()), "one read, one payment; the reply moved no money");
    assert_eq!(sorted(net.payee.received_in().await), sorted(paid.clone()), "the owner got exactly what the reader paid");
    assert!(!net.payer.privileged(&owner).await, "a bound reply promotes nothing on the reader");

    let held = net.payer.held_cards().await;
    assert_eq!(held["cards"].as_array().map(Vec::len), Some(1), "{held}");
    assert_eq!(held["cards"][0]["card"]["profile"]["display_name"], "Maya v1");

    let (status, body) = net.payer.browse(&owner, "/index.md").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!((body["status"].as_str(), body["content_type"].as_str()), (Some("Ok"), Some("text/markdown")));
    assert_eq!(body["body"], "# Maya\n\nHello from the porch.");
    assert!(body["card"].is_null());
    paid.push(PAGE_MSAT);

    // Nothing there is still an answer the reader paid for.
    let (status, body) = net.payer.browse(&owner, "/missing.md").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "NotFound");
    paid.push(PAGE_MSAT);

    // A path the porch never serves is refused before paying.
    let (status, body) = net.payer.browse(&owner, "/../pages/index.md").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "porch_path_invalid");
    assert_eq!(sorted(net.payer.paid_out().await), sorted(paid.clone()));

    // A newer card replaces the held one; a rollback to an older one does not.
    *net.payee.front_door.card.lock().await = Some(card(&net.payee, 2));
    let (_, body) = net.payer.browse(&owner, PORCH_CARD_PATH).await;
    assert_eq!((body["card"]["card"]["seq"].as_u64(), body["card"]["stale"].as_bool()), (Some(2), None), "{body}");
    *net.payee.front_door.card.lock().await = Some(card(&net.payee, 1));
    let (_, body) = net.payer.browse(&owner, PORCH_CARD_PATH).await;
    assert_eq!((body["card"]["card"]["seq"].as_u64(), body["card"]["stale"].as_bool()), (Some(1), Some(true)), "{body}");
    paid.extend([PAGE_MSAT, PAGE_MSAT]);
    assert_eq!(sorted(net.payer.paid_out().await), sorted(paid.clone()));
    let held = net.payer.held_cards().await;
    assert_eq!(held["cards"][0]["card"]["seq"], 2, "{held}");
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn porch_read_without_a_session_pays_nothing() {
    // Connected, never Knocked: no session, so the read is refused before any
    // invoice. A read never pays admission on its own.
    let net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    *net.payee.front_door.card.lock().await = Some(card(&net.payee, 1));
    let (status, body) = net.payer.browse(&net.payee.id, PORCH_CARD_PATH).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "porch_knock_first");

    // Not connected at all.
    let unknown = *stranger().0.node_id();
    let (status, body) = net.payer.browse(&unknown, PORCH_CARD_PATH).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "porch_unreachable");

    assert!(net.payer.paid_out().await.is_empty());
    assert!(net.payee.received_in().await.is_empty());
    assert!(net.payer.held_cards().await["cards"].as_array().unwrap().is_empty());
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_porch_read_returns_busy_without_deadlocking_the_slot() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let owner = net.payee.id;
    let (status, body) = net.payer.compose(&owner, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    *net.payee.front_door.card.lock().await = Some(card(&net.payee, 1));
    let paid_before = net.payer.paid_out().await;

    // Hold the first read after payment, while it still owns the in-flight slot.
    net.payer.pause.arm_before_page_send();
    let first = net.payer.browse(&owner, PORCH_CARD_PATH);
    let second = async {
        net.payer.pause.reached().await;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            net.payer.browse(&owner, PORCH_CARD_PATH),
        )
        .await;
        let paid_after_busy = net.payer.paid_out().await;
        net.payer.pause.release();
        (
            result.expect("busy Browse request must return promptly"),
            paid_after_busy,
        )
    };
    let ((first_status, first_body), ((busy_status, busy_body), paid_after_busy)) =
        tokio::join!(first, second);

    assert_eq!(busy_status, StatusCode::CONFLICT, "{busy_body}");
    assert_eq!(busy_body["reason"], "porch_busy");
    assert_eq!(first_status, StatusCode::OK, "{first_body}");
    let mut expected = paid_before.clone();
    expected.push(PAGE_MSAT);
    assert_eq!(
        sorted(paid_after_busy),
        sorted(expected.clone()),
        "the busy request must not add a payment"
    );
    assert_eq!(sorted(net.payer.paid_out().await), sorted(expected.clone()));

    // Dropping the successful request's guard frees the slot for the next read.
    let (later_status, later_body) = net.payer.browse(&owner, PORCH_CARD_PATH).await;
    assert_eq!(later_status, StatusCode::OK, "{later_body}");
    expected.push(PAGE_MSAT);
    assert_eq!(sorted(net.payer.paid_out().await), sorted(expected));
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_requires_explicit_knock_before_browse_and_pays_nothing() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let owner = net.payee.id;
    let (status, body) = net.payer.compose(&owner, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    assert!(net.payer.sessions.has_session(&owner).await);
    assert!(net.payer.paid_on_connection(&owner).await);
    let paid_before = net.payer.paid_out().await;
    let received_before = net.payee.received_in().await;

    net.flap().await;
    assert!(
        net.payer.sessions.has_session(&owner).await,
        "reconnect should preserve the E2EE session"
    );
    assert!(
        !net.payer.paid_on_connection(&owner).await,
        "replacement connection must start without admission"
    );

    let (status, body) = net.payer.browse(&owner, PORCH_CARD_PATH).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "readmission_required");
    assert_eq!(net.payer.paid_out().await, paid_before);
    assert_eq!(net.payee.received_in().await, received_before);
    net.stop();
}
