//! Rooms MVP: the room binding on ordinary chat. Sender pays each member
//! through the room fan-out (one paid 1:1 chat per member, addressed to that
//! member); refusals (a bad binding, a room id that does not commit to the
//! roster, a member without the advert or an E2EE session) happen before any
//! quote or payment; the receiver admits a binding only if its roster holds
//! both ends; the room thread lists both directions, our per-member copies
//! as one entry.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use konsensus_api::room_binding;
use konsensus_api::state::AppState;
use konsensus_core::payloads::room::{RoomBinding, RoomRefusal};
use konsensus_core::types::{NodeId, PaymentProof, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_storage::Storage;
use serde_json::{json, Value};
use tower::ServiceExt;

const SALT: [u8; 16] = [0x5a; 16];
const ADVERT: &str = r#"Custom("room_binding_v1")"#;
const MNEMONICS: [&str; 4] = [
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
];
/// Each member's chat price (no trust discount), all distinct.
const PRICES: [u64; 4] = [2_000, 3_000, 5_000, 7_000];

struct Fixture {
    state: Arc<AppState>,
    transport: Arc<ConnectedStubTransport>,
    storage: Arc<MemStorage>,
    own: NodeId,
    /// Connected, each with an E2EE session and a price table.
    members: Vec<NodeId>,
}

impl Fixture {
    async fn new() -> Self {
        let storage = Arc::new(MemStorage::new());
        let mut state = test_state_with_storage_and_cipher(storage.clone() as Arc<dyn Storage>);
        let sessions = Arc::clone(&state.session_manager);
        let mut members = Vec::new();
        for mnemonic in MNEMONICS {
            members.push(setup_e2ee_session_with_mnemonic(&sessions, mnemonic).await);
        }
        let transport = Arc::new(ConnectedStubTransport::new(members.clone(), Arc::clone(&state.invoice_requests)));
        Arc::get_mut(&mut state).unwrap().transport = transport.clone();
        for (i, member) in members.iter().enumerate() {
            state.peer_ln_pubkeys.lock().await.insert(*member, format!("02{:02x}", i).repeat(16));
            let prices = HashMap::from([("communication".to_string(), PRICES[i])]);
            state.peer_prices.update(*member, prices, 850_000, 144, 0.0).await;
        }
        let own = *state.identity.node_id();
        Self { state, transport, storage, own, members }
    }

    fn price(&self, member: &NodeId) -> u64 {
        PRICES[self.members.iter().position(|m| m == member).unwrap()]
    }

    fn advertise(&self, members: &[NodeId]) {
        for m in members {
            self.transport.advertise(*m, &["X3dh", ADVERT]);
        }
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri).header("authorization", auth_header(&self.state));
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let req = req.body(body.map_or(Body::empty(), |b| Body::from(b.to_string()))).unwrap();
        let response = test_router(Arc::clone(&self.state)).oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn compose(&self, recipient: &str, is_room: bool, plaintext: &str) -> (StatusCode, Value) {
        self.call("POST", "/api/v1/messages/compose", Some(json!({"recipient": recipient, "is_room": is_room, "kind": 0, "plaintext": plaintext}))).await
    }

    fn sent(&self) -> Vec<(NodeId, konsensus_core::UkmEnvelope)> {
        self.transport.sent_envelopes.lock().unwrap().clone()
    }
}

/// The room of `ids` (any order) under the fixed test salt.
fn room(ids: &[NodeId]) -> RoomBinding {
    RoomBinding::with_salt(ids, SALT).unwrap()
}

/// A fresh room message id.
fn msg() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!("{:032x}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

/// A room chat with `binding` exactly as written (valid or not).
fn chat_with(binding: Value, msg: &str, text: &str) -> String {
    json!({"v": 1, "room": binding, "msg": msg, "text": text}).to_string()
}

fn room_chat(room: &RoomBinding, text: &str) -> String {
    chat_with(serde_json::to_value(room).unwrap(), &msg(), text)
}

/// `room`'s id and salt with another roster: a member swapping someone in.
fn swapped(room: &RoomBinding, members: &[NodeId]) -> String {
    let mut binding = room.clone();
    binding.roster = self::room(members).roster;
    room_chat(&binding, "swapped")
}

/// Fan-out to 3 members: each is paid its own price exactly once, on its own
/// envelope addressed to it (not to a room), so the room id stays encrypted.
#[tokio::test]
async fn a_bound_room_pays_each_member_its_own_price_on_an_envelope_to_that_member() {
    let f = Fixture::new().await;
    let others = &f.members[..3];
    f.advertise(others);
    let r = room(&[f.own, others[0], others[1], others[2]]);
    let (status, body) = f.compose(&r.id, true, &room_chat(&r, "hello room")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let expected: u64 = others.iter().map(|m| f.price(m)).sum();
    assert_eq!(expected, 10_000);
    assert_eq!(body["amount_msat"], expected, "{body}");
    assert_eq!(body["delivered"], true);
    let outcomes = body["member_outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 3, "self is never paid: {body}");
    let listed: Vec<&str> = outcomes.iter().map(|o| o["recipient"].as_str().unwrap()).collect();
    let mut want: Vec<String> = others.iter().map(NodeId::to_hex).collect();
    want.sort();
    assert_eq!(listed, want, "roster order");
    for o in outcomes {
        let member = NodeId::from_hex(o["recipient"].as_str().unwrap()).unwrap();
        assert_eq!((o["status"].as_str(), o["amount_msat"].as_u64()), (Some("settled"), Some(f.price(&member))), "{o}");
    }
    let sent = f.sent();
    assert_eq!(sent.len(), 3, "one envelope per member");
    for (peer, env) in &sent {
        assert_eq!(env.recipient, Recipient::Node(*peer), "addressed to the member, never Recipient::Room");
        assert_eq!(env.kind, 0, "ordinary chat: no new kind");
        assert_eq!(env.payment_proof.amount_msat, f.price(peer));
    }
}

/// A member whose node does not advertise `room_binding_v1`, or without an
/// E2EE session, is skipped before any quote: nothing paid, shown with a code.
#[tokio::test]
async fn members_without_the_advert_or_a_session_are_skipped_with_nothing_paid() {
    let f = Fixture::new().await;
    let (paid, old_node, no_session) = (f.members[0], f.members[1], f.members[2]);
    assert!(f.state.session_manager.remove_session(&no_session).await);
    f.advertise(&[paid, no_session]);
    let r = room(&[f.own, paid, old_node, no_session]);
    let (status, body) = f.compose(&r.id, true, &room_chat(&r, "partial")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], f.price(&paid), "{body}");
    let by = |m: &NodeId| body["member_outcomes"].as_array().unwrap().iter().find(|o| o["recipient"] == m.to_hex()).unwrap().clone();
    assert_eq!(by(&paid)["status"], "settled");
    assert_eq!((by(&old_node)["status"].as_str(), by(&old_node)["amount_msat"].as_u64()), (Some("refused"), Some(0)));
    assert_eq!(by(&old_node)["code"], "room_binding_unsupported");
    assert_eq!((by(&no_session)["status"].as_str(), by(&no_session)["amount_msat"].as_u64()), (Some("refused"), Some(0)));
    assert_eq!(by(&no_session)["code"], "room_member_no_session");
    assert_eq!(f.sent().len(), 1, "only the reachable member got a paid envelope");

    // Nobody reachable: every member shown, nothing paid, nothing sent.
    let r = room(&[f.own, old_node]);
    let (status, body) = f.compose(&r.id, true, &room_chat(&r, "alone")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!((body["amount_msat"].as_u64(), body["delivered"].as_bool()), (Some(0), Some(false)));
    assert_eq!(body["member_outcomes"][0]["code"], "room_binding_unsupported");
    assert_eq!(f.sent().len(), 1);
}

/// Refused by our own node before any quote, reservation or payment.
#[tokio::test]
async fn a_bad_binding_is_refused_before_anything_is_paid() {
    let f = Fixture::new().await;
    let [a, b, c, d] = [f.members[0], f.members[1], f.members[2], f.members[3]];
    f.advertise(&[a, b, c, d]);
    let with_us = room(&[f.own, a, b]);
    let not_us = room(&[a, b, c]);
    let mut five = with_us.clone();
    five.roster = [f.own, a, b, c, d].iter().map(NodeId::to_hex).collect();
    five.roster.sort();
    let mut unsorted = with_us.clone();
    unsorted.roster.reverse();
    let id = with_us.id.as_str();
    let (other_id, c_hex) = ("f".repeat(64), c.to_hex());
    let cases: Vec<(&str, bool, String, &str)> = vec![
        // We are not in the roster.
        (&not_us.id, true, room_chat(&not_us, "x"), "room_sender_not_member"),
        (&with_us.roster[1], false, room_chat(&not_us, "x"), "room_sender_not_member"),
        // Five members; an unsorted roster.
        (id, true, room_chat(&five, "x"), "room_binding_invalid"),
        (id, true, room_chat(&unsorted, "x"), "room_binding_invalid"),
        // Empty text, unknown field, no msg.
        (id, true, room_chat(&with_us, ""), "room_binding_invalid"),
        (id, true, chat_with(json!({"id": id, "roster": with_us.roster, "salt": with_us.salt, "epoch": 2}), &msg(), "x"), "room_binding_invalid"),
        (id, true, json!({"v": 1, "room": with_us, "text": "x"}).to_string(), "room_binding_invalid"),
        // The room send's recipient is not the binding's room id.
        (&other_id, true, room_chat(&with_us, "x"), "room_binding_invalid"),
        // Codex #155: the room id of [us, a, b] with b swapped for c, or c
        // added: the id commits to the roster, so both are refused, as a
        // fan-out or as a 1:1 leg to the outsider.
        (id, true, swapped(&with_us, &[f.own, a, c]), "room_binding_invalid"),
        (id, true, swapped(&with_us, &[f.own, a, b, c]), "room_binding_invalid"),
        (&c_hex, false, swapped(&with_us, &[f.own, a, c]), "room_binding_invalid"),
    ];
    // Each is proven not dispatched (#115), so a client releases its reservation.
    let refused = |status: StatusCode, body: &Value, reason: &str| {
        assert_eq!((status, body["code"].as_str(), body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("not_dispatched"), Some(reason)), "{body}");
    };
    for (recipient, is_room, plaintext, reason) in cases {
        let (status, body) = f.compose(recipient, is_room, &plaintext).await;
        refused(status, &body, reason);
    }
    // One member at a time (ordinary 1:1 compose): the recipient must be in
    // the roster, advertise the binding, and have an E2EE session.
    let (status, body) = f.compose(&c.to_hex(), false, &room_chat(&with_us, "x")).await;
    refused(status, &body, "room_recipient_not_member");
    f.transport.peer_capabilities.lock().unwrap().remove(&a);
    let (status, body) = f.compose(&a.to_hex(), false, &room_chat(&with_us, "x")).await;
    refused(status, &body, "room_binding_unsupported");
    assert!(f.state.session_manager.remove_session(&b).await);
    let (status, body) = f.compose(&b.to_hex(), false, &room_chat(&with_us, "x")).await;
    refused(status, &body, "room_member_no_session");
    assert!(f.sent().is_empty(), "nothing sent");
    assert!(f.transport.raw_frames.lock().unwrap().is_empty(), "no invoice requested");
}

/// A 1:1 room chat is an ordinary operation: once journaled, a retry replays
/// it from the journal even if the member's advert is gone meanwhile, so a
/// paid chat never turns into a "not dispatched" the client would drop.
#[tokio::test]
async fn a_journaled_room_chat_replays_without_the_advert() {
    let f = Fixture::new().await;
    let a = f.members[0];
    f.advertise(&[a]);
    let body = json!({"recipient": a.to_hex(), "is_room": false, "kind": 0,
        "plaintext": room_chat(&room(&[f.own, a]), "once"), "operation_id": "5d2c1f0e-8a4b-4c3d-9e2f-1a2b3c4d5e6f"});
    let (status, first) = f.call("POST", "/api/v1/messages/compose", Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["amount_msat"], f.price(&a));
    f.transport.peer_capabilities.lock().unwrap().remove(&a);
    let (status, again) = f.call("POST", "/api/v1/messages/compose", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!((again["operation_id"].clone(), again["payment_hash"].clone()), (first["operation_id"].clone(), first["payment_hash"].clone()));
    let ids: std::collections::HashSet<_> = f.sent().iter().map(|(_, env)| env.id).collect();
    assert_eq!(ids.len(), 1, "one paid envelope, re-delivered at most");
}

/// Receive side: the roster must hold both the sender and this node. Plain
/// chat, undecryptable chat and other kinds carry no binding.
#[test]
fn the_receiver_admits_a_binding_only_with_both_ends_in_the_roster() {
    let (own, sender, other) = (NodeId::from_bytes([1; 32]), NodeId::from_bytes([2; 32]), NodeId::from_bytes([3; 32]));
    let chat = |ids: &[NodeId]| room_chat(&room(ids), "hi");
    let admit = |from: &NodeId, kind: u16, text: Option<&str>| room_binding::admit_incoming(&own, from, kind, text);
    let r = room(&[own, sender, other]);
    assert_eq!(admit(&sender, 0, Some(&chat(&[own, sender, other]))).unwrap().unwrap(), r);
    assert_eq!(admit(&sender, 0, Some(&chat(&[own, other]))), Err(RoomRefusal::SenderNotMember));
    assert_eq!(admit(&sender, 0, Some(&chat(&[sender, other]))), Err(RoomRefusal::RecipientNotMember));
    // A member reusing the room id with a new roster: refused, whoever sends it.
    let outsider = NodeId::from_bytes([4; 32]);
    assert_eq!(admit(&sender, 0, Some(&swapped(&r, &[own, sender, outsider]))), Err(RoomRefusal::Invalid("room id does not commit to this roster and salt")));
    assert_eq!(admit(&sender, 0, Some(&swapped(&r, &[own, sender]))), Err(RoomRefusal::Invalid("room id does not commit to this roster and salt")));
    assert!(matches!(admit(&sender, 0, Some(&chat_with(json!({"id": r.id, "roster": [own.to_hex()], "salt": r.salt}), &msg(), "hi"))), Err(RoomRefusal::Invalid(_))));
    assert_eq!(admit(&sender, 0, Some("hello")), Ok(None));
    assert_eq!(admit(&sender, 0, None), Ok(None), "undecryptable: nothing to check");
    assert_eq!(admit(&other, 1, Some(&chat(&[own, sender]))), Ok(None), "only chat (kind 0) is bound");
    assert!(room_binding::is_candidate(0) && !room_binding::is_candidate(1), "every chat is held until admitted");
    assert_eq!(RoomRefusal::SenderNotMember.code(), "room_sender_not_member");
}

async fn store(f: &Fixture, sender: NodeId, recipient: NodeId, plaintext: &str, n: u8) {
    let proof = PaymentProof::new([n; 32], [n; 32], 1_000);
    let env = UkmEnvelopeBuilder::new(0, sender, Recipient::Node(recipient), b"ct".to_vec(), proof).build();
    f.storage.store_message(&env).await.unwrap();
    f.storage.store_message_plaintext(&env.id, &test_plaintext_cipher().encrypt(plaintext.as_bytes()).unwrap()).await.unwrap();
}

/// The room thread (`?room=`) lists both directions: received chats bound to
/// that room, and our own room messages, each once with its per-member
/// copies. Another room, plain chat and a binding without both ends are left out.
#[tokio::test]
async fn the_room_thread_lists_both_directions_our_copies_once() {
    let f = Fixture::new().await;
    let (a, b, stranger) = (f.members[0], f.members[1], f.members[2]);
    let r = room(&[f.own, a, b]);
    store(&f, a, f.own, &room_chat(&r, "from a"), 1).await;
    store(&f, b, f.own, &room_chat(&r, "from b"), 2).await;
    store(&f, a, f.own, "plain 1:1", 3).await;
    store(&f, a, f.own, &room_chat(&RoomBinding::with_salt(&[f.own, a, b], [1; 16]).unwrap(), "other room"), 4).await;
    store(&f, stranger, f.own, &room_chat(&r, "not a member"), 5).await;
    // Our own: one message to both members (two copies), one to a only.
    let (both, one) = (msg(), msg());
    let ours = |m: &str, text: &str| chat_with(serde_json::to_value(&r).unwrap(), m, text);
    store(&f, f.own, a, &ours(&both, "to the room"), 6).await;
    store(&f, f.own, b, &ours(&both, "to the room"), 7).await;
    store(&f, f.own, a, &ours(&one, "retry to a"), 8).await;
    store(&f, f.own, stranger, &ours(&msg(), "to an outsider"), 9).await;

    let (status, body) = f.call("GET", &format!("/api/v1/messages?room={}", r.id), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entries = body.as_array().unwrap();
    let text = |m: &Value| serde_json::from_str::<Value>(m["plaintext"].as_str().unwrap()).unwrap()["text"].as_str().unwrap().to_string();
    let mut texts: Vec<String> = entries.iter().map(text).collect();
    texts.sort();
    assert_eq!(texts, ["from a", "from b", "retry to a", "to the room"], "{body}");
    for m in entries {
        assert_eq!(m["room"], serde_json::to_value(&r).unwrap());
    }
    let sent = entries.iter().find(|m| text(m) == "to the room").unwrap();
    assert_eq!((sent["recipient"].as_str(), sent["payment_amount_msat"].as_u64()), (Some(r.id.as_str()), Some(2_000)), "{sent}");
    assert_eq!(sent["room_msg"], both);
    let mut members = vec![a.to_hex(), b.to_hex()];
    members.sort();
    let copies: Vec<&str> = sent["copies"].as_array().unwrap().iter().map(|c| c["recipient"].as_str().unwrap()).collect();
    assert_eq!(copies, members, "{sent}");
    assert_eq!(entries.iter().find(|m| text(m) == "retry to a").unwrap()["copies"].as_array().unwrap().len(), 1);
    assert!(entries.iter().filter(|m| m["sender"] != f.own.to_hex()).all(|m| m.get("copies").is_none()));
    let (_, limited) = f.call("GET", &format!("/api/v1/messages?room={}&limit=1", r.id), None).await;
    assert_eq!(limited.as_array().unwrap().len(), 1, "limit counts entries, not copies");

    let (_, all) = f.call("GET", "/api/v1/messages", None).await;
    let plain = all.as_array().unwrap().iter().find(|m| m["plaintext"] == "plain 1:1").unwrap();
    assert!(plain.get("room").is_none(), "ordinary chat has no room: {plain}");
    for bad in ["not-a-room", "0123456789abcdef0123456789abcdef"] {
        let (status, _) = f.call("GET", &format!("/api/v1/messages?room={bad}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = f.call("GET", &format!("/api/v1/messages?room={}&peer={}", r.id, a.to_hex()), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Codex #155 probe `review_room_thread_includes_own_sent_chat`, on SQLite:
/// after a fan-out the sender's room thread holds that message once, with a
/// copy per member, and a member's reply.
#[tokio::test]
async fn a_sent_room_message_is_in_the_thread_once_on_sqlite() {
    let mut f = Fixture::new().await;
    Arc::get_mut(&mut f.state).unwrap().storage = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let others = &f.members[..3];
    f.advertise(others);
    let r = room(&[f.own, others[0], others[1], others[2]]);
    let (status, sent) = f.compose(&r.id, true, &room_chat(&r, "our room message")).await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let proof = PaymentProof::new([9; 32], [9; 32], 1_000);
    let reply = UkmEnvelopeBuilder::new(0, others[1], Recipient::Node(f.own), b"ct".to_vec(), proof).build();
    f.state.storage.store_message(&reply).await.unwrap();
    f.state.storage.store_message_plaintext(&reply.id, &test_plaintext_cipher().encrypt(room_chat(&r, "reply").as_bytes()).unwrap()).await.unwrap();
    let (status, thread) = f.call("GET", &format!("/api/v1/messages?room={}", r.id), None).await;
    assert_eq!(status, StatusCode::OK, "{thread}");
    let thread = thread.as_array().unwrap();
    assert_eq!(thread.len(), 2, "{thread:?}");
    let ours = thread.iter().find(|m| m["sender"] == f.own.to_hex()).expect("our sent room message");
    assert_eq!(ours["copies"].as_array().unwrap().len(), 3, "{ours}");
    assert_eq!(ours["payment_amount_msat"], sent["amount_msat"], "{ours}");
    assert!(thread.iter().any(|m| m["sender"] == others[1].to_hex()));
}

/// Codex #155 probe `room_one_member_without_session_must_not_pay_first_contact`:
/// a 1:1 room chat to a connected member that advertises the binding but has
/// no E2EE session is refused before any quote; the real (shared mock)
/// ledger shows zero spend and no invoice is asked for. A room never pays
/// first contact.
#[tokio::test(start_paused = true)]
async fn a_one_member_room_chat_without_a_session_pays_nothing() {
    use konsensus_core::traits::lightning::LightningProvider;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let wallet = Arc::new(konsensus_lightning::shared_mock::SharedMockProvider::new(&path, "a", 100_000).unwrap());
    let payee = Arc::new(konsensus_lightning::shared_mock::SharedMockProvider::new(&path, "b", 0).unwrap());
    let mut state = test_state_with_lightning(wallet.clone());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let asked = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let transport = Arc::new(ConnectedStubTransport::new(vec![peer], Arc::clone(&state.invoice_requests)).with_invoice_responder({
        let asked = asked.clone();
        move |request_id, _hint| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let inv = futures::executor::block_on(payee.create_invoice(2_000, &format!("konsensus:{request_id}:message=2000"), 55)).unwrap();
            Some(konsensus_api::state::InvoiceResponseData { recipient: peer, bolt11: inv.bolt11, payment_hash: inv.payment_hash })
        }
    }));
    transport.advertise(peer, &[ADVERT]);
    Arc::get_mut(&mut state).unwrap().transport = transport;
    assert!(!state.session_manager.has_session(&peer).await);
    let r = room(&[*state.identity.node_id(), peer]);
    for operation_id in [None, Some("7e3f0c2a-1b4d-4e5f-8a9b-0c1d2e3f4a5b")] {
        let body = json!({"recipient": peer.to_hex(), "kind": 0, "plaintext": room_chat(&r, "room hello"), "max_total_msat": 14_000, "operation_id": operation_id});
        let req = Request::builder().method("POST").uri("/api/v1/messages/compose")
            .header("authorization", auth_header(&state)).header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let response = test_router(Arc::clone(&state)).oneshot(req).await.unwrap();
        let status = response.status();
        let body: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap()).unwrap();
        assert_eq!((status, body["code"].as_str(), body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("not_dispatched"), Some("room_member_no_session")), "{body}");
    }
    assert_eq!(100_000 - wallet.get_balance_msat().await.unwrap(), 0, "nothing spent");
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0, "no invoice asked for");
}

/// A journaled 1:1 room chat that never paid (here: over its cap) re-enters
/// the paying path on retry; if the member's session is gone by then, it is
/// refused again before any quote, never sent as a paid first contact.
#[tokio::test]
async fn an_unpaid_journaled_room_chat_rechecks_the_session() {
    let f = Fixture::new().await;
    let a = f.members[0];
    f.advertise(&[a]);
    let body = json!({"recipient": a.to_hex(), "is_room": false, "kind": 0, "max_total_msat": 1_000,
        "plaintext": room_chat(&room(&[f.own, a]), "capped"), "operation_id": "0f1e2d3c-4b5a-4968-8776-655443322110"});
    let (status, first) = f.call("POST", "/api/v1/messages/compose", Some(body.clone())).await;
    assert_ne!(status, StatusCode::OK, "over its cap: {first}");
    assert!(f.sent().is_empty());
    let prices = HashMap::from([("communication".to_string(), 500)]);
    f.state.peer_prices.update(a, prices, 850_000, 144, 0.0).await;
    assert!(f.state.session_manager.remove_session(&a).await);
    let (status, again) = f.call("POST", "/api/v1/messages/compose", Some(body)).await;
    assert_eq!((status, again["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_member_no_session")), "{again}");
    assert!(f.sent().is_empty(), "nothing sent");
    assert!(f.transport.raw_frames.lock().unwrap().is_empty(), "no invoice requested");
}

#[tokio::test]
async fn status_advertises_room_binding_v1() {
    let f = Fixture::new().await;
    let (status, body) = f.call("GET", "/api/v1/status", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["api_capabilities"].as_array().unwrap().iter().any(|c| c == "room_binding_v1"), "{body}");
}
