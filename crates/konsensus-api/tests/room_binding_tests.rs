//! Rooms MVP: the room binding on ordinary chat. Sender pays each member
//! through the room fan-out (one paid 1:1 chat per member, addressed to that
//! member); refusals happen before any quote or payment; the receiver admits
//! a binding only if its roster holds both ends; the message list groups by
//! room id.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use konsensus_api::room_binding;
use konsensus_api::state::AppState;
use konsensus_core::payloads::room::RoomRefusal;
use konsensus_core::types::{NodeId, PaymentProof, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_storage::Storage;
use serde_json::{json, Value};
use tower::ServiceExt;

const ROOM: &str = "0123456789abcdef0123456789abcdef";
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

fn sorted(ids: &[NodeId]) -> Vec<String> {
    let mut roster: Vec<String> = ids.iter().map(NodeId::to_hex).collect();
    roster.sort();
    roster
}

fn room_chat(roster: &[String], text: &str) -> String {
    json!({"v": 1, "room": {"id": ROOM, "roster": roster}, "text": text}).to_string()
}

/// Fan-out to 3 members: each is paid its own price exactly once, on its own
/// envelope addressed to it (not to a room), so the room id stays encrypted.
#[tokio::test]
async fn a_bound_room_pays_each_member_its_own_price_on_an_envelope_to_that_member() {
    let f = Fixture::new().await;
    let others = &f.members[..3];
    f.advertise(others);
    let roster = sorted(&[f.own, others[0], others[1], others[2]]);
    let (status, body) = f.compose(ROOM, true, &room_chat(&roster, "hello room")).await;
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
    let roster = sorted(&[f.own, paid, old_node, no_session]);
    let (status, body) = f.compose(ROOM, true, &room_chat(&roster, "partial")).await;
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
    let roster = sorted(&[f.own, old_node]);
    let (status, body) = f.compose(ROOM, true, &room_chat(&roster, "alone")).await;
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
    let with_us = sorted(&[f.own, a, b]);
    let cases: Vec<(&str, bool, String, &str)> = vec![
        // We are not in the roster.
        (ROOM, true, room_chat(&sorted(&[a, b, c]), "x"), "room_sender_not_member"),
        (&with_us[1], false, room_chat(&sorted(&[a, b, c]), "x"), "room_sender_not_member"),
        // Five members.
        (ROOM, true, room_chat(&sorted(&[f.own, a, b, c, d]), "x"), "room_binding_invalid"),
        // Unsorted roster.
        (ROOM, true, room_chat(&[with_us[2].clone(), with_us[1].clone(), with_us[0].clone()], "x"), "room_binding_invalid"),
        // Empty text, unknown field.
        (ROOM, true, room_chat(&with_us, ""), "room_binding_invalid"),
        (ROOM, true, json!({"v": 1, "room": {"id": ROOM, "roster": with_us, "epoch": 2}, "text": "x"}).to_string(), "room_binding_invalid"),
        // The room send's recipient is not the binding's room id.
        ("ffffffffffffffffffffffffffffffff", true, room_chat(&with_us, "x"), "room_binding_invalid"),
    ];
    for (recipient, is_room, plaintext, reason) in cases {
        let (status, body) = f.compose(recipient, is_room, &plaintext).await;
        assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some(reason)), "{plaintext}: {body}");
    }
    // One member at a time (ordinary 1:1 compose): the recipient must be in
    // the roster and advertise the binding.
    let (status, body) = f.compose(&c.to_hex(), false, &room_chat(&with_us, "x")).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_recipient_not_member")), "{body}");
    f.transport.peer_capabilities.lock().unwrap().remove(&a);
    let (status, body) = f.compose(&a.to_hex(), false, &room_chat(&with_us, "x")).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_binding_unsupported")), "{body}");
    assert!(f.sent().is_empty(), "nothing sent");
    assert!(f.transport.raw_frames.lock().unwrap().is_empty(), "no invoice requested");
}

/// Receive side: the roster must hold both the sender and this node. Plain
/// chat, undecryptable chat and other kinds carry no binding.
#[test]
fn the_receiver_admits_a_binding_only_with_both_ends_in_the_roster() {
    let (own, sender, other) = (NodeId::from_bytes([1; 32]), NodeId::from_bytes([2; 32]), NodeId::from_bytes([3; 32]));
    let chat = |ids: &[NodeId]| room_chat(&sorted(ids), "hi");
    let admit = |from: &NodeId, kind: u16, text: Option<&str>| room_binding::admit_incoming(&own, from, kind, text);
    assert_eq!(admit(&sender, 0, Some(&chat(&[own, sender, other]))).unwrap().unwrap().id, ROOM);
    assert_eq!(admit(&sender, 0, Some(&chat(&[own, other]))), Err(RoomRefusal::SenderNotMember));
    assert_eq!(admit(&sender, 0, Some(&chat(&[sender, other]))), Err(RoomRefusal::RecipientNotMember));
    assert!(matches!(admit(&sender, 0, Some(&room_chat(&sorted(&[own]), "hi"))), Err(RoomRefusal::Invalid(_))));
    assert_eq!(admit(&sender, 0, Some("hello")), Ok(None));
    assert_eq!(admit(&sender, 0, None), Ok(None), "undecryptable: nothing to check");
    assert_eq!(admit(&other, 1, Some(&chat(&[own, sender]))), Ok(None), "only chat (kind 0) is bound");
    assert_eq!(RoomRefusal::SenderNotMember.code(), "room_sender_not_member");
}

async fn store(f: &Fixture, sender: NodeId, recipient: NodeId, plaintext: &str, n: u8) {
    let proof = PaymentProof::new([n; 32], [n; 32], 1_000);
    let env = UkmEnvelopeBuilder::new(0, sender, Recipient::Node(recipient), b"ct".to_vec(), proof).build();
    f.storage.store_message(&env).await.unwrap();
    f.storage.store_message_plaintext(&env.id, &test_plaintext_cipher().encrypt(plaintext.as_bytes()).unwrap()).await.unwrap();
}

/// The receiver groups by room id: `?room=` lists that room's chats, each
/// with its binding; a binding that lists neither end is never grouped.
#[tokio::test]
async fn the_message_list_groups_chats_by_room_id() {
    let f = Fixture::new().await;
    let (a, b, stranger) = (f.members[0], f.members[1], f.members[2]);
    let roster = sorted(&[f.own, a, b]);
    store(&f, a, f.own, &room_chat(&roster, "from a"), 1).await;
    store(&f, b, f.own, &room_chat(&roster, "from b"), 2).await;
    store(&f, a, f.own, "plain 1:1", 3).await;
    store(&f, a, f.own, &json!({"v": 1, "room": {"id": "fedcba9876543210fedcba9876543210", "roster": roster}, "text": "other room"}).to_string(), 4).await;
    store(&f, stranger, f.own, &room_chat(&roster, "not a member"), 5).await;

    let (status, body) = f.call("GET", &format!("/api/v1/messages?room={ROOM}"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut texts: Vec<String> = body.as_array().unwrap().iter().map(|m| {
        assert_eq!(m["room"]["id"], ROOM);
        assert_eq!(m["room"]["roster"], json!(roster));
        serde_json::from_str::<Value>(m["plaintext"].as_str().unwrap()).unwrap()["text"].as_str().unwrap().to_string()
    }).collect();
    texts.sort();
    assert_eq!(texts, ["from a", "from b"], "{body}");

    let (_, all) = f.call("GET", "/api/v1/messages", None).await;
    let plain = all.as_array().unwrap().iter().find(|m| m["plaintext"] == "plain 1:1").unwrap();
    assert!(plain.get("room").is_none(), "ordinary chat has no room: {plain}");
    let (status, _) = f.call("GET", "/api/v1/messages?room=not-a-room", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn status_advertises_room_binding_v1() {
    let f = Fixture::new().await;
    let (status, body) = f.call("GET", "/api/v1/status", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["api_capabilities"].as_array().unwrap().iter().any(|c| c == "room_binding_v1"), "{body}");
}
