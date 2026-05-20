//! Discovery and federation payloads — peer endorsements, content announcements,
//! and topic subscriptions.
//!
//! These structs are serialized to JSON, encrypted via Double Ratchet, and
//! transported as UKM envelopes with kinds 520-523 (WebContent 500-599 category).
//!
//! # Capacity limits
//! Hard caps are enforced by the sender and validated by the receiver:
//! - [`MAX_ENDORSEMENTS`] — maximum peers in a single [`PeerEndorseList`]
//! - [`MAX_TAGS`] — maximum tags on content/topic payloads
//! - [`MAX_SUMMARY`] — maximum byte length of a content summary string
//! - [`MAX_NOTE`] — maximum byte length of a free-text note string
//!
//! # Security model
//! All payloads travel through the existing E2EE pipeline (Noise transport +
//! Double Ratchet). No plaintext content at any layer. Every envelope still
//! passes through the payment gate (fail-closed).

use serde::{Deserialize, Serialize};

/// Maximum number of peer endorsements in a single [`PeerEndorseList`].
pub const MAX_ENDORSEMENTS: usize = 500;

/// Maximum number of tags on a content announcement or topic payload.
pub const MAX_TAGS: usize = 10;

/// Maximum byte length of a content summary string.
pub const MAX_SUMMARY: usize = 512;

/// Maximum byte length of a free-text note string.
pub const MAX_NOTE: usize = 256;

// ── PeerEndorseList (KIND_PEER_ENDORSE = 520) ─────────────────────────────

/// A single peer endorsement — a node vouching for one other peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndorsement {
    /// The endorsed peer's node public key (hex-encoded compressed secp256k1).
    pub node_pubkey: String,

    /// Optional human-readable note about why this peer is trusted.
    /// Must not exceed [`MAX_NOTE`] bytes when encoded as UTF-8.
    #[serde(default)]
    pub note: String,
}

/// A list of peer endorsements from the sending node.
///
/// Sent as `KIND_PEER_ENDORSE` (520). Receivers may use endorsements as
/// social-graph signals when deciding whether to whitelist new peers.
/// Endorsements are advisory — they never bypass the whitelist gate.
///
/// At most [`MAX_ENDORSEMENTS`] entries may appear in a single message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndorseList {
    /// The endorsed peers. Capped at [`MAX_ENDORSEMENTS`] entries.
    pub endorsements: Vec<PeerEndorsement>,

    /// Block height at signing time. Used for staleness detection.
    #[serde(default)]
    pub block_height: u64,
}

impl PeerEndorseList {
    /// Returns `true` if the payload is within all capacity limits.
    pub fn is_valid(&self) -> bool {
        if self.endorsements.len() > MAX_ENDORSEMENTS {
            return false;
        }
        self.endorsements
            .iter()
            .all(|e| e.note.len() <= MAX_NOTE)
    }
}

// ── ContentAnnouncement (KIND_CONTENT_ANNOUNCE = 521) ─────────────────────

/// An announcement that a node has published new content.
///
/// Sent as `KIND_CONTENT_ANNOUNCE` (521). Subscribers can use this to
/// proactively fetch new pages via `KIND_PAGE_REQUEST` rather than polling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentAnnouncement {
    /// The content path being announced (e.g., "/blog/new-post.md").
    pub path: String,

    /// Short human-readable summary of the content.
    /// Must not exceed [`MAX_SUMMARY`] bytes when encoded as UTF-8.
    #[serde(default)]
    pub summary: String,

    /// Classification tags (e.g., ["rust", "bitcoin", "sovereignty"]).
    /// At most [`MAX_TAGS`] entries.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Price to fetch this content in millisatoshis.
    /// If `None`, the node's default page price applies.
    #[serde(default)]
    pub price_msat: Option<u64>,

    /// Block height at the time of publication.
    #[serde(default)]
    pub block_height: u64,
}

impl ContentAnnouncement {
    /// Returns `true` if the payload is within all capacity limits.
    pub fn is_valid(&self) -> bool {
        self.summary.len() <= MAX_SUMMARY && self.tags.len() <= MAX_TAGS
    }
}

// ── TopicSubscribeRequest (KIND_TOPIC_SUBSCRIBE = 522) ────────────────────

/// A request to subscribe to a named topic feed on a peer node.
///
/// Sent as `KIND_TOPIC_SUBSCRIBE` (522). The peer node may accept or reject
/// the subscription based on its own whitelist policy. Accepted subscriptions
/// result in future `KIND_CONTENT_ANNOUNCE` messages being forwarded to the
/// subscriber.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicSubscribeRequest {
    /// The topic name to subscribe to (e.g., "bitcoin", "dev-notes").
    pub topic: String,

    /// Preferred content tags. The peer node will filter announcements to
    /// those matching at least one of these tags. Empty means "all content".
    /// At most [`MAX_TAGS`] entries.
    #[serde(default)]
    pub filter_tags: Vec<String>,

    /// Optional note to the publisher explaining the subscription intent.
    /// Must not exceed [`MAX_NOTE`] bytes when encoded as UTF-8.
    #[serde(default)]
    pub note: String,
}

impl TopicSubscribeRequest {
    /// Returns `true` if the payload is within all capacity limits.
    pub fn is_valid(&self) -> bool {
        self.filter_tags.len() <= MAX_TAGS && self.note.len() <= MAX_NOTE
    }
}

// ── TopicUnsubscribeRequest (KIND_TOPIC_UNSUBSCRIBE = 523) ────────────────

/// A request to unsubscribe from a named topic feed on a peer node.
///
/// Sent as `KIND_TOPIC_UNSUBSCRIBE` (523). The peer node removes the sender
/// from the subscriber list for the named topic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicUnsubscribeRequest {
    /// The topic name to unsubscribe from.
    pub topic: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PeerEndorseList ────────────────────────────────────────────────────

    #[test]
    fn peer_endorse_list_roundtrip() {
        let list = PeerEndorseList {
            endorsements: vec![
                PeerEndorsement {
                    node_pubkey: "02a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
                    note: "Trusted developer peer".to_string(),
                },
                PeerEndorsement {
                    node_pubkey: "03deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef01".to_string(),
                    note: String::new(),
                },
            ],
            block_height: 900_000,
        };

        let json = serde_json::to_string(&list).unwrap();
        let decoded: PeerEndorseList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, decoded);
        assert_eq!(decoded.endorsements.len(), 2);
    }

    #[test]
    fn peer_endorse_list_defaults() {
        let json = r#"{"endorsements":[]}"#;
        let list: PeerEndorseList = serde_json::from_str(json).unwrap();
        assert!(list.endorsements.is_empty());
        assert_eq!(list.block_height, 0);
    }

    #[test]
    fn peer_endorse_list_is_valid_empty() {
        let list = PeerEndorseList {
            endorsements: vec![],
            block_height: 0,
        };
        assert!(list.is_valid());
    }

    #[test]
    fn peer_endorse_list_exceeds_max_endorsements() {
        let list = PeerEndorseList {
            endorsements: (0..=MAX_ENDORSEMENTS)
                .map(|i| PeerEndorsement {
                    node_pubkey: format!("pubkey_{i:064x}"),
                    note: String::new(),
                })
                .collect(),
            block_height: 0,
        };
        // MAX_ENDORSEMENTS + 1 entries — must fail validation
        assert!(!list.is_valid());
    }

    #[test]
    fn peer_endorse_list_note_too_long() {
        let long_note = "x".repeat(MAX_NOTE + 1);
        let list = PeerEndorseList {
            endorsements: vec![PeerEndorsement {
                node_pubkey: "02aabbcc".to_string(),
                note: long_note,
            }],
            block_height: 0,
        };
        assert!(!list.is_valid());
    }

    #[test]
    fn peer_endorse_list_note_at_limit() {
        let note_at_limit = "x".repeat(MAX_NOTE);
        let list = PeerEndorseList {
            endorsements: vec![PeerEndorsement {
                node_pubkey: "02aabbcc".to_string(),
                note: note_at_limit,
            }],
            block_height: 0,
        };
        assert!(list.is_valid());
    }

    // ── ContentAnnouncement ────────────────────────────────────────────────

    #[test]
    fn content_announcement_roundtrip() {
        let ann = ContentAnnouncement {
            path: "/blog/sovereign-money.md".to_string(),
            summary: "Why Bitcoin is the only truly sovereign money.".to_string(),
            tags: vec!["bitcoin".to_string(), "sovereignty".to_string()],
            price_msat: Some(100),
            block_height: 900_001,
        };

        let json = serde_json::to_string(&ann).unwrap();
        let decoded: ContentAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(ann, decoded);
    }

    #[test]
    fn content_announcement_defaults() {
        let json = r#"{"path":"/index.md"}"#;
        let ann: ContentAnnouncement = serde_json::from_str(json).unwrap();
        assert_eq!(ann.summary, "");
        assert!(ann.tags.is_empty());
        assert_eq!(ann.price_msat, None);
        assert_eq!(ann.block_height, 0);
    }

    #[test]
    fn content_announcement_is_valid() {
        let ann = ContentAnnouncement {
            path: "/p.md".to_string(),
            summary: "Short".to_string(),
            tags: vec!["a".to_string()],
            price_msat: None,
            block_height: 0,
        };
        assert!(ann.is_valid());
    }

    #[test]
    fn content_announcement_summary_too_long() {
        let ann = ContentAnnouncement {
            path: "/p.md".to_string(),
            summary: "x".repeat(MAX_SUMMARY + 1),
            tags: vec![],
            price_msat: None,
            block_height: 0,
        };
        assert!(!ann.is_valid());
    }

    #[test]
    fn content_announcement_summary_at_limit() {
        let ann = ContentAnnouncement {
            path: "/p.md".to_string(),
            summary: "x".repeat(MAX_SUMMARY),
            tags: vec![],
            price_msat: None,
            block_height: 0,
        };
        assert!(ann.is_valid());
    }

    #[test]
    fn content_announcement_too_many_tags() {
        let ann = ContentAnnouncement {
            path: "/p.md".to_string(),
            summary: String::new(),
            tags: (0..=MAX_TAGS).map(|i| format!("tag{i}")).collect(),
            price_msat: None,
            block_height: 0,
        };
        assert!(!ann.is_valid());
    }

    #[test]
    fn content_announcement_tags_at_limit() {
        let ann = ContentAnnouncement {
            path: "/p.md".to_string(),
            summary: String::new(),
            tags: (0..MAX_TAGS).map(|i| format!("tag{i}")).collect(),
            price_msat: None,
            block_height: 0,
        };
        assert!(ann.is_valid());
    }

    // ── TopicSubscribeRequest ──────────────────────────────────────────────

    #[test]
    fn topic_subscribe_roundtrip() {
        let req = TopicSubscribeRequest {
            topic: "bitcoin".to_string(),
            filter_tags: vec!["lightning".to_string(), "taproot".to_string()],
            note: "Following your Bitcoin research".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: TopicSubscribeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn topic_subscribe_defaults() {
        let json = r#"{"topic":"sovereignty"}"#;
        let req: TopicSubscribeRequest = serde_json::from_str(json).unwrap();
        assert!(req.filter_tags.is_empty());
        assert_eq!(req.note, "");
    }

    #[test]
    fn topic_subscribe_is_valid() {
        let req = TopicSubscribeRequest {
            topic: "rust".to_string(),
            filter_tags: vec![],
            note: String::new(),
        };
        assert!(req.is_valid());
    }

    #[test]
    fn topic_subscribe_too_many_tags() {
        let req = TopicSubscribeRequest {
            topic: "rust".to_string(),
            filter_tags: (0..=MAX_TAGS).map(|i| format!("tag{i}")).collect(),
            note: String::new(),
        };
        assert!(!req.is_valid());
    }

    #[test]
    fn topic_subscribe_note_too_long() {
        let req = TopicSubscribeRequest {
            topic: "rust".to_string(),
            filter_tags: vec![],
            note: "n".repeat(MAX_NOTE + 1),
        };
        assert!(!req.is_valid());
    }

    #[test]
    fn topic_subscribe_note_at_limit() {
        let req = TopicSubscribeRequest {
            topic: "rust".to_string(),
            filter_tags: vec![],
            note: "n".repeat(MAX_NOTE),
        };
        assert!(req.is_valid());
    }

    // ── TopicUnsubscribeRequest ────────────────────────────────────────────

    #[test]
    fn topic_unsubscribe_roundtrip() {
        let req = TopicUnsubscribeRequest {
            topic: "bitcoin".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: TopicUnsubscribeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn topic_unsubscribe_empty_topic() {
        let json = r#"{"topic":""}"#;
        let req: TopicUnsubscribeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.topic, "");
    }

    // ── Constants ──────────────────────────────────────────────────────────

    #[test]
    fn capacity_constants_are_sensible() {
        assert_eq!(MAX_ENDORSEMENTS, 500);
        assert_eq!(MAX_TAGS, 10);
        assert_eq!(MAX_SUMMARY, 512);
        assert_eq!(MAX_NOTE, 256);
    }
}
