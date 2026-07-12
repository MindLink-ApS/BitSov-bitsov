//! UKM kind taxonomy — the `kind` field (u16) determines payload schema.
//!
//! # Ranges
//! - **0–99:** Communication (chat, long-form, reply, reaction, edit, delete, forward)
//! - **100–199:** Structured data (calendar events, RSVP, contacts)
//! - **200–299:** Files & media (file refs, inline images, voice memos)
//! - **300–399:** Collaboration (CRDT ops, document snapshots)
//! - **400–499:** Real-time signaling (call invite/answer/ICE/hangup)
//! - **500–599:** Web content (page requests/responses, manifests — sovereign browser)
//! - **900–999:** Control (typing, read receipts, presence, room ops, key exchange, MLS)
//! - **1000+:** Application extension space

// ── Communication (0–99) ───────────────────────────────────────────────

/// Short text message (chat bubble).
pub const KIND_CHAT: u16 = 0;
/// Long-form message (mail-style).
pub const KIND_LONGFORM: u16 = 1;
/// Reply to another message (references parent via `references` field).
pub const KIND_REPLY: u16 = 2;
/// Reaction (emoji) to another message.
pub const KIND_REACTION: u16 = 3;
/// Edit a previously sent message.
pub const KIND_EDIT: u16 = 4;
/// Delete / retract a previously sent message.
pub const KIND_DELETE: u16 = 5;
/// Forward a message from another conversation.
pub const KIND_FORWARD: u16 = 6;

// ── Structured Data (100–199) ──────────────────────────────────────────

/// Calendar event.
pub const KIND_CALENDAR_EVENT: u16 = 100;
/// RSVP response to a calendar event.
pub const KIND_RSVP: u16 = 101;
/// Shared contact card.
pub const KIND_CONTACT: u16 = 102;
/// Node profile (display name, bio, avatar, verified identities).
pub const KIND_PROFILE: u16 = 103;
/// Calendar event update.
pub const KIND_CALENDAR_UPDATE: u16 = 104;

// ── Files & Media (200–299) ────────────────────────────────────────────

/// File reference (metadata + encrypted blob pointer).
pub const KIND_FILE_REF: u16 = 200;
/// Inline image (small, embedded in payload).
pub const KIND_INLINE_IMAGE: u16 = 201;
/// Voice memo.
pub const KIND_VOICE_MEMO: u16 = 202;

// ── Collaboration (300–399) ────────────────────────────────────────────

/// CRDT operation (document edit).
pub const KIND_CRDT_OP: u16 = 300;
/// Document snapshot.
pub const KIND_DOC_SNAPSHOT: u16 = 301;

// ── Web Content (500–599) ──────────────────────────────────────────────

/// Page request — browser requests content at a path from a peer's node.
pub const KIND_PAGE_REQUEST: u16 = 500;
/// Page response — server returns content for a requested path.
pub const KIND_PAGE_RESPONSE: u16 = 501;
/// Web manifest — server advertises available pages and pricing.
pub const KIND_WEB_MANIFEST: u16 = 510;
/// Peer endorsement list — a node vouches for a set of peers it trusts.
pub const KIND_PEER_ENDORSE: u16 = 520;
/// Content announcement — a node advertises newly published content to subscribers.
pub const KIND_CONTENT_ANNOUNCE: u16 = 521;
/// Topic subscription request — a node subscribes to a named topic feed on a peer.
pub const KIND_TOPIC_SUBSCRIBE: u16 = 522;
/// Topic unsubscription request — a node unsubscribes from a named topic feed on a peer.
pub const KIND_TOPIC_UNSUBSCRIBE: u16 = 523;

// ── Real-time Signaling (400–499) ──────────────────────────────────────

/// Call invite. (Deferred — not implemented in v2.0)
pub const KIND_CALL_INVITE: u16 = 400;
/// Call answer. (Deferred)
pub const KIND_CALL_ANSWER: u16 = 401;
/// ICE candidate. (Deferred)
pub const KIND_ICE_CANDIDATE: u16 = 402;
/// Call hangup. (Deferred)
pub const KIND_CALL_HANGUP: u16 = 403;

// ── Control (900–999) ──────────────────────────────────────────────────

/// Typing indicator.
pub const KIND_TYPING: u16 = 900;
/// Read receipt.
pub const KIND_READ_RECEIPT: u16 = 901;
/// Presence update (online/offline/away).
pub const KIND_PRESENCE: u16 = 902;
/// Room creation.
pub const KIND_ROOM_CREATE: u16 = 910;
/// Room member invite.
pub const KIND_ROOM_INVITE: u16 = 911;
/// Room member join.
pub const KIND_ROOM_JOIN: u16 = 912;
/// Room member leave.
pub const KIND_ROOM_LEAVE: u16 = 913;
/// Room metadata update (name, avatar, etc.).
pub const KIND_ROOM_UPDATE: u16 = 914;
/// Key exchange message (PQXDH prekey bundle).
pub const KIND_KEY_EXCHANGE: u16 = 950;
/// MLS welcome message.
pub const KIND_MLS_WELCOME: u16 = 960;
/// MLS commit message.
pub const KIND_MLS_COMMIT: u16 = 961;
/// MLS proposal.
pub const KIND_MLS_PROPOSAL: u16 = 962;

// ── Relay Storage (600–699) ────────────────────────────────────────────
// Control kinds for the Tier-2 store-and-forward relay (RELAY_PROTOCOL.md,
// ADR-034). T2R3 adds the taxonomy + pricing surface ONLY — the relay engine is
// not implemented here. A relay holds only sealed ciphertext and never decrypts;
// relay storage is a paid service, separate from the sender→recipient message
// payment.

/// Relay register: a node asks a relay to hold messages for it while offline (600).
pub const KIND_RELAY_REGISTER: u16 = 600;

/// Relay deposit: a peer hands the relay a sealed envelope for an offline recipient (601).
pub const KIND_RELAY_DEPOSIT: u16 = 601;

/// Relay ack: recipient confirms receipt so the relay can delete the held envelope (602).
pub const KIND_RELAY_ACK: u16 = 602;

/// Relay drain: a node coming online collects its held envelopes (603).
pub const KIND_RELAY_DRAIN: u16 = 603;

/// Relay unregister: a node tells the relay to stop holding for it (604).
pub const KIND_RELAY_UNREGISTER: u16 = 604;

// ── Application Extension (1000+) ──────────────────────────────────────

/// Start of application extension space. Kinds >= 1000 are user-defined.
pub const KIND_APP_EXT_START: u16 = 1000;

/// Categorization of kind ranges for pricing and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KindCategory {
    /// Chat, replies, reactions, edits, deletes, forwards (0–99).
    Communication,
    /// Calendar events, RSVPs, contacts (100–199).
    StructuredData,
    /// File refs, images, voice memos (200–299).
    FilesMedia,
    /// CRDT ops, document snapshots (300–399).
    Collaboration,
    /// Call signaling (400–499).
    RealTimeSignaling,
    /// Web content: page requests, responses, manifests (500–599).
    WebContent,
    /// Tier-2 relay storage control: register, deposit, ack, drain, unregister
    /// (600–699). A paid service kind — the relay store-and-forwards sealed
    /// ciphertext (RELAY_PROTOCOL.md, ADR-034); it never decrypts.
    Storage,
    /// Typing, receipts, presence, room ops, key exchange, MLS (900–999).
    Control,
    /// Application extensions (1000+).
    AppExtension,
    /// Unknown / reserved range.
    Unknown,
}

impl KindCategory {
    /// Classify a kind value into its category.
    pub fn from_kind(kind: u16) -> Self {
        match kind {
            0..=99 => Self::Communication,
            100..=199 => Self::StructuredData,
            200..=299 => Self::FilesMedia,
            300..=399 => Self::Collaboration,
            400..=499 => Self::RealTimeSignaling,
            500..=599 => Self::WebContent,
            600..=699 => Self::Storage,
            900..=999 => Self::Control,
            1000.. => Self::AppExtension,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_category_classification() {
        assert_eq!(KindCategory::from_kind(KIND_CHAT), KindCategory::Communication);
        assert_eq!(KindCategory::from_kind(KIND_LONGFORM), KindCategory::Communication);
        assert_eq!(KindCategory::from_kind(KIND_REPLY), KindCategory::Communication);
        assert_eq!(KindCategory::from_kind(KIND_CALENDAR_EVENT), KindCategory::StructuredData);
        assert_eq!(KindCategory::from_kind(KIND_FILE_REF), KindCategory::FilesMedia);
        assert_eq!(KindCategory::from_kind(KIND_CRDT_OP), KindCategory::Collaboration);
        assert_eq!(KindCategory::from_kind(KIND_CALL_INVITE), KindCategory::RealTimeSignaling);
        assert_eq!(KindCategory::from_kind(KIND_TYPING), KindCategory::Control);
        assert_eq!(KindCategory::from_kind(KIND_MLS_WELCOME), KindCategory::Control);
        assert_eq!(KindCategory::from_kind(KIND_PAGE_REQUEST), KindCategory::WebContent);
        assert_eq!(KindCategory::from_kind(KIND_PAGE_RESPONSE), KindCategory::WebContent);
        assert_eq!(KindCategory::from_kind(KIND_WEB_MANIFEST), KindCategory::WebContent);
        assert_eq!(KindCategory::from_kind(1000), KindCategory::AppExtension);
        assert_eq!(KindCategory::from_kind(600), KindCategory::Storage);
    }

    /// Verify every defined KIND_* constant falls in the correct category.
    #[test]
    fn all_communication_kinds_are_communication() {
        for kind in [
            KIND_CHAT,
            KIND_LONGFORM,
            KIND_REPLY,
            KIND_REACTION,
            KIND_EDIT,
            KIND_DELETE,
            KIND_FORWARD,
        ] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::Communication,
                "KIND {kind} must be Communication"
            );
        }
    }

    #[test]
    fn all_structured_data_kinds_are_structured_data() {
        for kind in [
            KIND_CALENDAR_EVENT,
            KIND_RSVP,
            KIND_CONTACT,
            KIND_PROFILE,
            KIND_CALENDAR_UPDATE,
        ] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::StructuredData,
                "KIND {kind} must be StructuredData"
            );
        }
    }

    #[test]
    fn all_files_media_kinds_are_files_media() {
        for kind in [KIND_FILE_REF, KIND_INLINE_IMAGE, KIND_VOICE_MEMO] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::FilesMedia,
                "KIND {kind} must be FilesMedia"
            );
        }
    }

    #[test]
    fn all_collaboration_kinds_are_collaboration() {
        for kind in [KIND_CRDT_OP, KIND_DOC_SNAPSHOT] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::Collaboration,
                "KIND {kind} must be Collaboration"
            );
        }
    }

    #[test]
    fn all_realtime_signaling_kinds_are_realtime() {
        for kind in [
            KIND_CALL_INVITE,
            KIND_CALL_ANSWER,
            KIND_ICE_CANDIDATE,
            KIND_CALL_HANGUP,
        ] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::RealTimeSignaling,
                "KIND {kind} must be RealTimeSignaling"
            );
        }
    }

    #[test]
    fn all_web_content_kinds_are_web_content() {
        for kind in [
            KIND_PAGE_REQUEST,
            KIND_PAGE_RESPONSE,
            KIND_WEB_MANIFEST,
            KIND_PEER_ENDORSE,
            KIND_CONTENT_ANNOUNCE,
            KIND_TOPIC_SUBSCRIBE,
            KIND_TOPIC_UNSUBSCRIBE,
        ] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::WebContent,
                "KIND {kind} must be WebContent"
            );
        }
    }

    #[test]
    fn all_control_kinds_are_control() {
        for kind in [
            KIND_TYPING,
            KIND_READ_RECEIPT,
            KIND_PRESENCE,
            KIND_ROOM_CREATE,
            KIND_ROOM_INVITE,
            KIND_ROOM_JOIN,
            KIND_ROOM_LEAVE,
            KIND_ROOM_UPDATE,
            KIND_KEY_EXCHANGE,
            KIND_MLS_WELCOME,
            KIND_MLS_COMMIT,
            KIND_MLS_PROPOSAL,
        ] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::Control,
                "KIND {kind} must be Control"
            );
        }
    }

    #[test]
    fn app_extension_start_is_app_extension() {
        assert_eq!(
            KindCategory::from_kind(KIND_APP_EXT_START),
            KindCategory::AppExtension
        );
        assert_eq!(
            KindCategory::from_kind(u16::MAX),
            KindCategory::AppExtension,
            "u16::MAX should be in AppExtension range"
        );
    }

    /// Verify the "unknown" gap ranges (600-899) are classified correctly.
    #[test]
    fn unknown_gap_ranges() {
        // 600-699 is now the relay Storage category (T2R3); 700-899 stays reserved.
        for kind in [700, 800, 899] {
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::Unknown,
                "KIND {kind} must be Unknown (reserved gap)"
            );
        }
    }

    /// Verify category boundaries are exact.
    #[test]
    fn category_boundaries() {
        // Communication: 0-99
        assert_eq!(KindCategory::from_kind(0), KindCategory::Communication);
        assert_eq!(KindCategory::from_kind(99), KindCategory::Communication);
        assert_eq!(KindCategory::from_kind(100), KindCategory::StructuredData);

        // StructuredData: 100-199
        assert_eq!(KindCategory::from_kind(199), KindCategory::StructuredData);
        assert_eq!(KindCategory::from_kind(200), KindCategory::FilesMedia);

        // FilesMedia: 200-299
        assert_eq!(KindCategory::from_kind(299), KindCategory::FilesMedia);
        assert_eq!(KindCategory::from_kind(300), KindCategory::Collaboration);

        // Collaboration: 300-399
        assert_eq!(KindCategory::from_kind(399), KindCategory::Collaboration);
        assert_eq!(KindCategory::from_kind(400), KindCategory::RealTimeSignaling);

        // RealTimeSignaling: 400-499
        assert_eq!(KindCategory::from_kind(499), KindCategory::RealTimeSignaling);
        assert_eq!(KindCategory::from_kind(500), KindCategory::WebContent);

        // WebContent: 500-599
        assert_eq!(KindCategory::from_kind(599), KindCategory::WebContent);
        assert_eq!(KindCategory::from_kind(600), KindCategory::Storage);

        // Storage (relay): 600-699
        assert_eq!(KindCategory::from_kind(699), KindCategory::Storage);
        assert_eq!(KindCategory::from_kind(700), KindCategory::Unknown);

        // Unknown: 700-899
        assert_eq!(KindCategory::from_kind(899), KindCategory::Unknown);
        assert_eq!(KindCategory::from_kind(900), KindCategory::Control);

        // Control: 900-999
        assert_eq!(KindCategory::from_kind(999), KindCategory::Control);
        assert_eq!(KindCategory::from_kind(1000), KindCategory::AppExtension);
    }

    /// No two KIND_* constants within the same range share a value.
    #[test]
    fn no_duplicate_kind_constants() {
        let all_kinds: Vec<u16> = vec![
            KIND_CHAT, KIND_LONGFORM, KIND_REPLY, KIND_REACTION, KIND_EDIT,
            KIND_DELETE, KIND_FORWARD,
            KIND_CALENDAR_EVENT, KIND_RSVP, KIND_CONTACT, KIND_PROFILE, KIND_CALENDAR_UPDATE,
            KIND_FILE_REF, KIND_INLINE_IMAGE, KIND_VOICE_MEMO,
            KIND_CRDT_OP, KIND_DOC_SNAPSHOT,
            KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE, KIND_WEB_MANIFEST,
            KIND_PEER_ENDORSE, KIND_CONTENT_ANNOUNCE, KIND_TOPIC_SUBSCRIBE, KIND_TOPIC_UNSUBSCRIBE,
            KIND_CALL_INVITE, KIND_CALL_ANSWER, KIND_ICE_CANDIDATE, KIND_CALL_HANGUP,
            KIND_TYPING, KIND_READ_RECEIPT, KIND_PRESENCE,
            KIND_ROOM_CREATE, KIND_ROOM_INVITE, KIND_ROOM_JOIN, KIND_ROOM_LEAVE, KIND_ROOM_UPDATE,
            KIND_KEY_EXCHANGE, KIND_MLS_WELCOME, KIND_MLS_COMMIT, KIND_MLS_PROPOSAL,
            KIND_RELAY_REGISTER, KIND_RELAY_DEPOSIT, KIND_RELAY_ACK, KIND_RELAY_DRAIN,
            KIND_RELAY_UNREGISTER,
            KIND_APP_EXT_START,
        ];
        let mut seen = std::collections::HashSet::new();
        for kind in &all_kinds {
            assert!(
                seen.insert(kind),
                "duplicate KIND constant: {kind}"
            );
        }
    }

    /// T2R3: the relay control kinds (600-699) classify as the Storage category.
    #[test]
    fn kind_category_relay_storage() {
        for kind in [
            KIND_RELAY_REGISTER,
            KIND_RELAY_DEPOSIT,
            KIND_RELAY_ACK,
            KIND_RELAY_DRAIN,
            KIND_RELAY_UNREGISTER,
        ] {
            assert!(
                (600..=699).contains(&kind),
                "relay control kind {kind} must live in the 600-699 Storage range"
            );
            assert_eq!(
                KindCategory::from_kind(kind),
                KindCategory::Storage,
                "kind {kind} must classify as Storage"
            );
        }
        // The five control operations are distinct.
        let distinct: std::collections::HashSet<u16> = [
            KIND_RELAY_REGISTER, KIND_RELAY_DEPOSIT, KIND_RELAY_ACK,
            KIND_RELAY_DRAIN, KIND_RELAY_UNREGISTER,
        ]
        .into_iter()
        .collect();
        assert_eq!(distinct.len(), 5);
    }
}
