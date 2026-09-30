//! Rooms MVP: an optional room binding on ordinary chat (kind 0).
//!
//! A room is a random id and a fixed roster of 2 to [`MAX_ROOM_MEMBERS`] node
//! ids, chosen at creation and never changed: a membership change is a new
//! room. There is no new kind, no room state on the node and no room
//! authority. A room message is one ordinary paid 1:1 chat to each other
//! member, each encrypted with that pair's session; its plaintext is
//!
//! ```json
//! {"v":1,"room":{"id":"<32 lowercase hex>","roster":["<node id>", ...]},"text":"..."}
//! ```
//!
//! Any chat plaintext that is a JSON object with a top-level `room` key is a
//! room chat and must be valid; anything else is ordinary chat, unchanged. A
//! receiver refuses a binding whose roster does not contain both the sender
//! and itself ([`RoomBinding::check`]).

use serde::{Deserialize, Serialize};

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

/// Which room a chat belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomBinding {
    /// 32 lowercase hex characters (16 random bytes), chosen at creation.
    pub id: String,
    /// Node ids (64 lowercase hex), 2 to [`MAX_ROOM_MEMBERS`], sorted
    /// ascending (so distinct, and one roster has one spelling). No member
    /// is first: the room has no creator authority.
    pub roster: Vec<String>,
}

/// The plaintext of a room-bound chat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomChat {
    pub v: u8,
    pub room: RoomBinding,
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
        if chat.text.is_empty() {
            return Err(RoomRefusal::Invalid("empty text"));
        }
        chat.room.validate()?;
        Ok(Some(chat))
    }
}

impl RoomBinding {
    fn validate(&self) -> Result<(), RoomRefusal> {
        if !is_lower_hex(&self.id, 32) {
            return Err(RoomRefusal::Invalid("room id must be 32 lowercase hex"));
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

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn node(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn roster(bytes: &[u8]) -> Vec<String> {
        bytes.iter().map(|b| node(*b).to_hex()).collect()
    }

    fn chat(roster: &[String]) -> String {
        serde_json::json!({"v": 1, "room": {"id": ID, "roster": roster}, "text": "hi"}).to_string()
    }

    #[test]
    fn ordinary_chat_has_no_binding() {
        for text in ["hello", "", "{not json", "{\"text\":\"a json note\"}", "[1,2]", "  {\"roomy\":1}"] {
            assert_eq!(RoomChat::parse(text), Ok(None), "{text}");
        }
    }

    #[test]
    fn a_room_chat_parses_with_2_to_4_sorted_members() {
        let parsed = RoomChat::parse(&chat(&roster(&[1, 2, 3, 4]))).unwrap().unwrap();
        assert_eq!(parsed.room.roster.len(), MAX_ROOM_MEMBERS);
        assert_eq!(parsed.text, "hi");
        assert_eq!(parsed.room.members(), vec![node(1), node(2), node(3), node(4)]);
        assert!(RoomChat::parse(&chat(&roster(&[1, 2]))).unwrap().is_some());
    }

    #[test]
    fn a_malformed_binding_is_refused_not_treated_as_text() {
        let invalid = |plaintext: &str| matches!(RoomChat::parse(plaintext), Err(RoomRefusal::Invalid(_)));
        assert!(invalid(&chat(&roster(&[1, 2, 3, 4, 5]))), "5 members");
        assert!(invalid(&chat(&roster(&[1]))), "alone");
        assert!(invalid(&chat(&roster(&[2, 1]))), "unsorted");
        assert!(invalid(&chat(&roster(&[1, 1, 2]))), "duplicate");
        assert!(invalid(&chat(&[node(1).to_hex(), node(0xab).to_hex().to_uppercase()])), "uppercase");
        assert!(invalid(&chat(&[node(1).to_hex(), node(2).to_hex()[..62].to_string()])), "short id");
        let r = roster(&[1, 2]);
        assert!(invalid(&serde_json::json!({"v": 1, "room": {"id": "x", "roster": r}, "text": "hi"}).to_string()), "room id");
        assert!(invalid(&serde_json::json!({"v": 2, "room": {"id": ID, "roster": r}, "text": "hi"}).to_string()), "version");
        assert!(invalid(&serde_json::json!({"v": 1, "room": {"id": ID, "roster": r}, "text": ""}).to_string()), "empty text");
        assert!(invalid(&serde_json::json!({"v": 1, "room": {"id": ID, "roster": r}}).to_string()), "no text");
        assert!(invalid(&serde_json::json!({"v": 1, "room": {"id": ID, "roster": r, "epoch": 1}, "text": "hi"}).to_string()), "unknown binding field");
        assert!(invalid(&serde_json::json!({"v": 1, "room": {"id": ID, "roster": r}, "text": "hi", "seq": 1}).to_string()), "unknown field");
        assert!(invalid(&serde_json::json!({"room": null, "text": "hi"}).to_string()), "null room");
    }

    #[test]
    fn both_ends_must_be_in_the_roster() {
        let room = RoomChat::parse(&chat(&roster(&[1, 2, 3]))).unwrap().unwrap().room;
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
