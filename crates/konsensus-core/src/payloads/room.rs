//! Rooms MVP: an optional room binding on ordinary chat (kind 0).
//!
//! A room is a fixed roster of 2 to [`MAX_ROOM_MEMBERS`] node ids, chosen at
//! creation and never changed: a membership change is a new room. Its id
//! commits to that roster: `id = SHA-256(domain ‖ count ‖ sorted roster ‖
//! salt)` ([`room_id`]), with a random salt carried in the binding. Every
//! node recomputes it, so a binding that pairs a known room id with any other
//! roster is refused, and nobody (the creator included) has authority over
//! the room. There is no new kind and no room state on the node. A room
//! message is one ordinary paid 1:1 chat to each other member, each encrypted
//! with that pair's session; its plaintext is
//!
//! ```json
//! {"v":1,"room":{"id":"<64 hex>","roster":["<node id>", ...],"salt":"<32 hex>"},"msg":"<32 hex>","text":"..."}
//! ```
//!
//! `msg` is random per logical message and the same on every member's copy,
//! so the sender's node shows its per-member copies as one outgoing chat.
//!
//! Any chat plaintext that is a JSON object with a top-level `room` key is a
//! room chat and must be valid; anything else is ordinary chat, unchanged. A
//! receiver refuses a binding whose roster does not contain both the sender
//! and itself ([`RoomBinding::check`]).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::NodeId;

/// Room chat schema version.
pub const ROOM_CHAT_VERSION: u8 = 1;
/// Most members of a room, the sender included. The sender pays each other
/// member, so a send costs up to `MAX_ROOM_MEMBERS - 1` paid messages.
pub const MAX_ROOM_MEMBERS: usize = 4;
/// Advertised by a node that accepts room-bound chat: as `Capability::Custom`
/// in its federation Hello (peers see it in `GET /api/v1/peers` as
/// `Custom("room_binding_v1")`) and in its own `/status` `api_capabilities`.
/// A node without it shows the JSON as text, so nobody sends it a room chat.
pub const ROOM_BINDING_CAPABILITY: &str = "room_binding_v1";
/// Domain tag of [`room_id`].
pub const ROOM_ID_DOMAIN: &[u8] = b"bitsov/room-id/v1\0";
/// Salt bytes (32 lowercase hex in the binding).
pub const ROOM_SALT_LEN: usize = 16;

/// Which room a chat belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomBinding {
    /// 64 lowercase hex: [`room_id`] of `roster` and `salt`.
    pub id: String,
    /// Node ids (64 lowercase hex), 2 to [`MAX_ROOM_MEMBERS`], sorted
    /// ascending (so distinct, and one roster has one spelling). No member
    /// is first: the room has no creator authority.
    pub roster: Vec<String>,
    /// 32 lowercase hex (16 random bytes), chosen at creation, so two rooms
    /// of the same people are distinct rooms.
    pub salt: String,
}

/// The plaintext of a room-bound chat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomChat {
    pub v: u8,
    pub room: RoomBinding,
    /// 32 lowercase hex, random per logical message, identical on each
    /// member's copy.
    pub msg: String,
    pub text: String,
}

/// Why a room-bound chat was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoomRefusal {
    #[error("invalid room binding: {0}")]
    Invalid(&'static str),
    #[error("the sender is not in the room's roster")]
    SenderNotMember,
    #[error("the recipient is not in the room's roster")]
    RecipientNotMember,
}

impl RoomRefusal {
    /// Stable refusal code, as the API's `reason`.
    pub fn code(&self) -> &'static str {
        match self {
            RoomRefusal::Invalid(_) => "room_binding_invalid",
            RoomRefusal::SenderNotMember => "room_sender_not_member",
            RoomRefusal::RecipientNotMember => "room_recipient_not_member",
        }
    }
}

fn is_lower_hex(id: &str, len: usize) -> bool {
    id.len() == len && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `id` has the shape of a room id (64 lowercase hex).
pub fn is_room_id(id: &str) -> bool {
    is_lower_hex(id, 64)
}

/// The id of the room of `roster` (sorted ascending, distinct) and `salt`:
/// `SHA-256(ROOM_ID_DOMAIN ‖ len(roster) as u8 ‖ roster[0] ‖ … ‖ salt)`, each
/// node id as its 32 bytes, in lowercase hex.
pub fn room_id(roster: &[NodeId], salt: &[u8; ROOM_SALT_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(ROOM_ID_DOMAIN);
    h.update([roster.len() as u8]);
    for member in roster {
        h.update(member.as_bytes());
    }
    h.update(salt);
    hex::encode(h.finalize())
}

impl RoomChat {
    /// `Ok(None)` for ordinary chat. A JSON object with a top-level `room`
    /// key must be a valid room chat.
    pub fn parse(plaintext: &str) -> Result<Option<Self>, RoomRefusal> {
        if !plaintext.trim_start().starts_with('{') {
            return Ok(None);
        }
        let Ok(object) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(plaintext) else {
            return Ok(None);
        };
        if !object.contains_key("room") {
            return Ok(None);
        }
        let chat: RoomChat = serde_json::from_value(serde_json::Value::Object(object)).map_err(|_| RoomRefusal::Invalid("not a room chat"))?;
        if chat.v != ROOM_CHAT_VERSION {
            return Err(RoomRefusal::Invalid("unsupported version"));
        }
        if !is_lower_hex(&chat.msg, 32) {
            return Err(RoomRefusal::Invalid("msg must be 32 lowercase hex"));
        }
        if chat.text.is_empty() {
            return Err(RoomRefusal::Invalid("empty text"));
        }
        chat.room.validate()?;
        Ok(Some(chat))
    }
}

impl RoomBinding {
    /// A new room of `members` (any order) with a fresh random salt.
    pub fn create(members: &[NodeId]) -> Result<Self, RoomRefusal> {
        use rand::RngCore;
        let mut salt = [0u8; ROOM_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::with_salt(members, salt)
    }

    /// The room of `members` (any order) and `salt`.
    pub fn with_salt(members: &[NodeId], salt: [u8; ROOM_SALT_LEN]) -> Result<Self, RoomRefusal> {
        let mut roster: Vec<String> = members.iter().map(NodeId::to_hex).collect();
        roster.sort();
        let room = RoomBinding { id: String::new(), roster, salt: hex::encode(salt) };
        let id = room.derived_id().ok_or(RoomRefusal::Invalid("roster entries must be node ids"))?;
        let room = RoomBinding { id, ..room };
        room.validate()?;
        Ok(room)
    }

    /// [`room_id`] of this roster and salt, if they parse.
    fn derived_id(&self) -> Option<String> {
        let salt: [u8; ROOM_SALT_LEN] = hex::decode(&self.salt).ok()?.try_into().ok()?;
        let members = self.roster.iter().map(|id| NodeId::from_hex(id).ok()).collect::<Option<Vec<_>>>()?;
        Some(room_id(&members, &salt))
    }

    fn validate(&self) -> Result<(), RoomRefusal> {
        if !is_room_id(&self.id) {
            return Err(RoomRefusal::Invalid("room id must be 64 lowercase hex"));
        }
        if !is_lower_hex(&self.salt, 2 * ROOM_SALT_LEN) {
            return Err(RoomRefusal::Invalid("salt must be 32 lowercase hex"));
        }
        if !(2..=MAX_ROOM_MEMBERS).contains(&self.roster.len()) {
            return Err(RoomRefusal::Invalid("a room has 2 to 4 members"));
        }
        if !self.roster.iter().all(|id| is_lower_hex(id, 64)) {
            return Err(RoomRefusal::Invalid("roster entries must be 64 lowercase hex node ids"));
        }
        if !self.roster.windows(2).all(|w| w[0] < w[1]) {
            return Err(RoomRefusal::Invalid("roster must be sorted ascending without duplicates"));
        }
        if self.derived_id().as_deref() != Some(self.id.as_str()) {
            return Err(RoomRefusal::Invalid("room id does not commit to this roster and salt"));
        }
        Ok(())
    }

    pub fn contains(&self, node: &NodeId) -> bool {
        self.roster.binary_search(&node.to_hex()).is_ok()
    }

    /// Both ends of this 1:1 chat must be in the roster.
    pub fn check(&self, sender: &NodeId, recipient: &NodeId) -> Result<(), RoomRefusal> {
        if !self.contains(sender) {
            return Err(RoomRefusal::SenderNotMember);
        }
        if sender == recipient || !self.contains(recipient) {
            return Err(RoomRefusal::RecipientNotMember);
        }
        Ok(())
    }

    /// The roster as node ids.
    pub fn members(&self) -> Vec<NodeId> {
        self.roster.iter().filter_map(|id| NodeId::from_hex(id).ok()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; ROOM_SALT_LEN] = [7; ROOM_SALT_LEN];
    const MSG: &str = "00112233445566778899aabbccddeeff";

    fn node(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn nodes(bytes: &[u8]) -> Vec<NodeId> {
        bytes.iter().map(|b| node(*b)).collect()
    }

    fn room(bytes: &[u8]) -> RoomBinding {
        RoomBinding::with_salt(&nodes(bytes), SALT).unwrap()
    }

    fn chat_json(room: serde_json::Value) -> String {
        serde_json::json!({"v": 1, "room": room, "msg": MSG, "text": "hi"}).to_string()
    }

    fn chat(room: &RoomBinding) -> String {
        chat_json(serde_json::to_value(room).unwrap())
    }

    /// The binding as written, with `roster` replaced (and the id kept).
    fn with_roster(room: &RoomBinding, roster: Vec<String>) -> String {
        chat_json(serde_json::json!({"id": room.id, "roster": roster, "salt": room.salt}))
    }

    #[test]
    fn ordinary_chat_has_no_binding() {
        for text in ["hello", "", "{not json", "{\"text\":\"a json note\"}", "[1,2]", "  {\"roomy\":1}"] {
            assert_eq!(RoomChat::parse(text), Ok(None), "{text}");
        }
    }

    #[test]
    fn a_room_chat_parses_with_2_to_4_sorted_members() {
        let parsed = RoomChat::parse(&chat(&room(&[4, 2, 3, 1]))).unwrap().unwrap();
        assert_eq!(parsed.room.roster.len(), MAX_ROOM_MEMBERS);
        assert_eq!((parsed.text.as_str(), parsed.msg.as_str()), ("hi", MSG));
        assert_eq!(parsed.room.members(), nodes(&[1, 2, 3, 4]), "created in any order, stored sorted");
        assert!(RoomChat::parse(&chat(&room(&[1, 2]))).unwrap().is_some());
    }

    /// The id is the domain-tagged hash of the sorted roster and the salt:
    /// any other roster (or salt) under the same id is refused, whoever sends it.
    #[test]
    fn the_room_id_commits_to_the_roster_and_salt() {
        let r = room(&[1, 2, 3]);
        let mut pre = ROOM_ID_DOMAIN.to_vec();
        pre.push(3);
        for b in [1u8, 2, 3] {
            pre.extend_from_slice(&[b; 32]);
        }
        pre.extend_from_slice(&SALT);
        assert_eq!(r.id, hex::encode(Sha256::digest(&pre)), "documented preimage");
        assert_eq!(r, room(&[3, 1, 2]), "deterministic for one roster and salt");
        assert_ne!(r.id, RoomBinding::with_salt(&nodes(&[1, 2, 3]), [8; ROOM_SALT_LEN]).unwrap().id, "the salt separates rooms");
        assert_ne!(RoomBinding::create(&nodes(&[1, 2])).unwrap().id, RoomBinding::create(&nodes(&[1, 2])).unwrap().id);

        let mismatch = |text: &str| RoomChat::parse(text) == Err(RoomRefusal::Invalid("room id does not commit to this roster and salt"));
        // An outsider swapped in, a member dropped, a member added: all refused.
        assert!(mismatch(&with_roster(&r, nodes(&[1, 2, 9]).iter().map(NodeId::to_hex).collect())));
        assert!(mismatch(&with_roster(&r, nodes(&[1, 2]).iter().map(NodeId::to_hex).collect())));
        assert!(mismatch(&with_roster(&r, nodes(&[1, 2, 3, 4]).iter().map(NodeId::to_hex).collect())));
        assert!(mismatch(&chat_json(serde_json::json!({"id": r.id, "roster": r.roster, "salt": "08".repeat(16)}))));
        assert!(mismatch(&chat_json(serde_json::json!({"id": "ab".repeat(32), "roster": r.roster, "salt": r.salt}))));
    }

    #[test]
    fn a_malformed_binding_is_refused_not_treated_as_text() {
        let invalid = |plaintext: &str| matches!(RoomChat::parse(plaintext), Err(RoomRefusal::Invalid(_)));
        let five: Vec<String> = nodes(&[1, 2, 3, 4, 5]).iter().map(NodeId::to_hex).collect();
        let r = room(&[1, 2]);
        assert!(invalid(&with_roster(&r, five)), "5 members");
        assert!(RoomBinding::with_salt(&nodes(&[1, 2, 3, 4, 5]), SALT).is_err());
        assert!(RoomBinding::with_salt(&nodes(&[1]), SALT).is_err(), "alone");
        assert!(RoomBinding::with_salt(&nodes(&[1, 1, 2]), SALT).is_err(), "duplicate");
        assert!(invalid(&with_roster(&r, vec![node(2).to_hex(), node(1).to_hex()])), "unsorted");
        assert!(invalid(&with_roster(&r, vec![node(1).to_hex(), node(0xab).to_hex().to_uppercase()])), "uppercase");
        assert!(invalid(&with_roster(&r, vec![node(1).to_hex(), node(2).to_hex()[..62].to_string()])), "short id");
        let v = serde_json::to_value(&r).unwrap();
        assert!(invalid(&chat_json(serde_json::json!({"id": &r.id[..32], "roster": r.roster, "salt": r.salt}))), "room id length");
        assert!(invalid(&chat_json(serde_json::json!({"id": r.id, "roster": r.roster}))), "no salt");
        assert!(invalid(&chat_json(serde_json::json!({"id": r.id, "roster": r.roster, "salt": "07"}))), "short salt");
        assert!(invalid(&serde_json::json!({"v": 2, "room": v, "msg": MSG, "text": "hi"}).to_string()), "version");
        assert!(invalid(&serde_json::json!({"v": 1, "room": v, "msg": MSG, "text": ""}).to_string()), "empty text");
        assert!(invalid(&serde_json::json!({"v": 1, "room": v, "msg": MSG}).to_string()), "no text");
        assert!(invalid(&serde_json::json!({"v": 1, "room": v, "text": "hi"}).to_string()), "no msg");
        assert!(invalid(&serde_json::json!({"v": 1, "room": v, "msg": "ABC", "text": "hi"}).to_string()), "bad msg");
        assert!(invalid(&chat_json(serde_json::json!({"id": r.id, "roster": r.roster, "salt": r.salt, "epoch": 1}))), "unknown binding field");
        assert!(invalid(&serde_json::json!({"v": 1, "room": v, "msg": MSG, "text": "hi", "seq": 1}).to_string()), "unknown field");
        assert!(invalid(&serde_json::json!({"room": null, "text": "hi"}).to_string()), "null room");
    }

    #[test]
    fn both_ends_must_be_in_the_roster() {
        let room = RoomChat::parse(&chat(&room(&[1, 2, 3]))).unwrap().unwrap().room;
        assert_eq!(room.check(&node(1), &node(3)), Ok(()));
        assert_eq!(room.check(&node(3), &node(1)), Ok(()), "no order: any member writes to any other");
        assert_eq!(room.check(&node(9), &node(1)), Err(RoomRefusal::SenderNotMember));
        assert_eq!(room.check(&node(1), &node(9)), Err(RoomRefusal::RecipientNotMember));
        assert_eq!(room.check(&node(1), &node(1)), Err(RoomRefusal::RecipientNotMember), "not to oneself");
        assert_eq!(RoomRefusal::SenderNotMember.code(), "room_sender_not_member");
        assert_eq!(RoomRefusal::RecipientNotMember.code(), "room_recipient_not_member");
        assert_eq!(RoomRefusal::Invalid("x").code(), "room_binding_invalid");
    }
}
