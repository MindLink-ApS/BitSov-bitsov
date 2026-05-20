//! Node profile payload — KIND_PROFILE (103).
//!
//! A [`NodeProfile`] advertises a node's public identity: display name, bio,
//! avatar, and cross-platform verified identities. Profiles are E2EE in transit
//! and stored only on the node.
//!
//! # Validation
//! Call [`NodeProfile::validate`] after construction or deserialization to enforce
//! 10 safety rules across five areas:
//! - **Text safety** (rules 1–6): NFC normalization, bidi-override rejection,
//!   length caps for name and bio.
//! - **Avatar limits** (rules 7–8): inline avatar ≤ 8 KiB; hashed avatar declared
//!   size ≤ 512 KiB.
//! - **Payload cap** (rule 9): total serialized JSON ≤ 12 KiB.
//! - **Freshness** (rule 10): timestamp within [now − 1 year, now + 5 minutes].

use chrono::Utc;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Re-export the kind constant for use alongside the payload type.
pub use crate::kind::KIND_PROFILE;

// ── Limits ────────────────────────────────────────────────────────────────────

const MAX_NAME_CHARS: usize = 48;
const MAX_BIO_CHARS: usize = 280;
const MAX_INLINE_AVATAR_BYTES: usize = 8_192; // 8 KiB
const MAX_HASHED_AVATAR_BYTES: u64 = 524_288; // 512 KiB
const MAX_PAYLOAD_BYTES: usize = 12_288; // 12 KiB
const VALID_TIMESTAMP_PAST_SECS: i64 = 365 * 24 * 3_600; // 1 year
const VALID_TIMESTAMP_FUTURE_SECS: i64 = 300; // 5 minutes

/// Bidirectional control characters that must not appear in user-visible strings.
///
/// These characters are used in "Trojan Source" and display-spoofing attacks to
/// make text appear different on screen from what it actually contains.
const BIDI_CHARS: &[char] = &[
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{061C}', // ARABIC LETTER MARK
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
];

// ── AvatarRef ─────────────────────────────────────────────────────────────────

/// Avatar data embedded directly in the profile payload (must be ≤ 8 KiB).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvatarInline {
    /// Raw image bytes, base64-encoded in JSON.
    #[serde(with = "serde_base64")]
    pub data: Vec<u8>,
    /// MIME type (e.g., `"image/jpeg"`, `"image/png"`, `"image/webp"`).
    pub mime_type: String,
}

/// Avatar referenced by blake3 hash for deferred retrieval (declared size ≤ 512 KiB).
///
/// The actual image is fetched separately via the file-transfer layer. The hash
/// ensures integrity when the image is eventually retrieved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvatarHashed {
    /// Blake3 hash of the avatar bytes, encoded as 64-character lowercase hex.
    pub hash: String,
    /// Declared byte size of the full avatar data. Must be ≤ 512 KiB.
    pub size_bytes: u64,
    /// MIME type (e.g., `"image/jpeg"`, `"image/png"`, `"image/webp"`).
    pub mime_type: String,
}

/// How an avatar is stored or referenced in a [`NodeProfile`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AvatarRef {
    /// Avatar bytes embedded directly in the payload (≤ 8 KiB raw).
    Inline(AvatarInline),
    /// Avatar referenced by blake3 hash; retrieved via file-transfer layer (declared size ≤ 512 KiB).
    Hashed(AvatarHashed),
}

// ── VerifiedIdentity ──────────────────────────────────────────────────────────

/// A cross-platform identity claim with a cryptographic or URL proof.
///
/// Examples: `{ platform: "github", handle: "alice", proof: "https://gist.github.com/..." }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Platform name (e.g., `"github"`, `"twitter"`, `"keybase"`, `"email"`).
    pub platform: String,
    /// Handle on the platform (e.g., `"alice"`, `"@alice"`, `"alice@example.com"`).
    pub handle: String,
    /// Cryptographic proof URL or signed statement.
    pub proof: String,
}

// ── NodeProfile ───────────────────────────────────────────────────────────────

/// Public node profile — the wire payload for `KIND_PROFILE` (103).
///
/// All fields are public by design: profile data is intended to be shared with
/// specific peers, though it is still E2EE in transit and stored only on the node.
///
/// After constructing or deserializing a `NodeProfile`, call [`validate`][Self::validate]
/// to enforce the 10 safety rules before using or forwarding the profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeProfile {
    /// Human-readable display name. Max 48 Unicode scalar values. Must be NFC-normalized;
    /// `validate()` normalizes in place and then checks remaining constraints.
    pub display_name: String,
    /// Short biography. Max 280 Unicode scalar values.
    #[serde(default)]
    pub bio: String,
    /// Optional avatar (inline ≤ 8 KiB or hashed reference with declared size ≤ 512 KiB).
    #[serde(default)]
    pub avatar: Option<AvatarRef>,
    /// Cross-platform verified identity claims (GitHub, Twitter, Keybase, email, etc.).
    #[serde(default)]
    pub verified_identities: Vec<VerifiedIdentity>,
    /// Unix timestamp (seconds UTC) when this profile was issued.
    pub timestamp: i64,
}

// ── ProfileValidationError ────────────────────────────────────────────────────

/// Errors returned by [`NodeProfile::validate`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileValidationError {
    /// Rule 2: display_name contains bidi override characters.
    #[error("display_name contains bidi override characters")]
    NameBidiOverride,
    /// Rule 3: display_name exceeds 48 Unicode chars.
    #[error("display_name exceeds 48 characters ({0} chars)")]
    NameTooLong(usize),
    /// Rule 5: bio contains bidi override characters.
    #[error("bio contains bidi override characters")]
    BioBidiOverride,
    /// Rule 6: bio exceeds 280 Unicode chars.
    #[error("bio exceeds 280 characters ({0} chars)")]
    BioTooLong(usize),
    /// Rule 7: inline avatar raw bytes exceed 8 KiB.
    #[error("inline avatar exceeds 8192 bytes ({0} bytes)")]
    InlineAvatarTooLarge(usize),
    /// Rule 8: hashed avatar declared size exceeds 512 KiB.
    #[error("hashed avatar declared size exceeds 524288 bytes ({0} bytes)")]
    HashedAvatarTooLarge(u64),
    /// Rule 9: total serialized JSON payload exceeds 12 KiB.
    #[error("serialized payload exceeds 12288 bytes ({0} bytes)")]
    PayloadTooLarge(usize),
    /// Rule 10: timestamp outside [now − 1 year, now + 5 minutes].
    #[error("timestamp {0} is outside the valid range [now-1y, now+5min]")]
    TimestampOutOfRange(i64),
}

// ── NodeProfile::validate ─────────────────────────────────────────────────────

impl NodeProfile {
    /// Validate and normalize this profile in place.
    ///
    /// Applies 10 rules in order:
    /// 1. NFC-normalize `display_name` (in place, not an error).
    /// 2. Reject `display_name` containing bidi override characters.
    /// 3. Reject `display_name` longer than 48 Unicode scalar values.
    /// 4. NFC-normalize `bio` (in place, not an error).
    /// 5. Reject `bio` containing bidi override characters.
    /// 6. Reject `bio` longer than 280 Unicode scalar values.
    /// 7. Reject inline avatar whose raw data exceeds 8 KiB (8 192 bytes).
    /// 8. Reject hashed avatar whose declared `size_bytes` exceeds 512 KiB (524 288 bytes).
    /// 9. Reject profiles whose total serialized JSON payload exceeds 12 KiB (12 288 bytes).
    /// 10. Reject profiles whose `timestamp` falls outside `[now − 1 year, now + 5 minutes]`.
    ///
    /// Returns `Ok(())` when all rules pass. The first violation encountered is returned.
    pub fn validate(&mut self) -> Result<(), ProfileValidationError> {
        // Rule 1 — NFC-normalize display_name (no error; normalization is silent).
        let normalized: String = self.display_name.nfc().collect();
        self.display_name = normalized;

        // Rule 2 — Reject bidi overrides in display_name.
        if self.display_name.chars().any(|c| BIDI_CHARS.contains(&c)) {
            return Err(ProfileValidationError::NameBidiOverride);
        }

        // Rule 3 — Max 48 Unicode scalar values.
        let name_chars = self.display_name.chars().count();
        if name_chars > MAX_NAME_CHARS {
            return Err(ProfileValidationError::NameTooLong(name_chars));
        }

        // Rule 4 — NFC-normalize bio (no error; normalization is silent).
        let normalized_bio: String = self.bio.nfc().collect();
        self.bio = normalized_bio;

        // Rule 5 — Reject bidi overrides in bio.
        if self.bio.chars().any(|c| BIDI_CHARS.contains(&c)) {
            return Err(ProfileValidationError::BioBidiOverride);
        }

        // Rule 6 — Max 280 Unicode scalar values.
        let bio_chars = self.bio.chars().count();
        if bio_chars > MAX_BIO_CHARS {
            return Err(ProfileValidationError::BioTooLong(bio_chars));
        }

        // Rules 7 & 8 — Avatar size constraints.
        if let Some(ref avatar) = self.avatar {
            match avatar {
                AvatarRef::Inline(inline) => {
                    if inline.data.len() > MAX_INLINE_AVATAR_BYTES {
                        return Err(ProfileValidationError::InlineAvatarTooLarge(
                            inline.data.len(),
                        ));
                    }
                }
                AvatarRef::Hashed(hashed) => {
                    if hashed.size_bytes > MAX_HASHED_AVATAR_BYTES {
                        return Err(ProfileValidationError::HashedAvatarTooLarge(
                            hashed.size_bytes,
                        ));
                    }
                }
            }
        }

        // Rule 9 — Total serialized payload ≤ 12 KiB.
        // Serialize after normalization so the size check reflects final wire bytes.
        let json =
            serde_json::to_vec(self).expect("NodeProfile is always serializable; this is a bug");
        if json.len() > MAX_PAYLOAD_BYTES {
            return Err(ProfileValidationError::PayloadTooLarge(json.len()));
        }

        // Rule 10 — Timestamp within [now − 1 year, now + 5 minutes].
        let now = Utc::now().timestamp();
        let min_ts = now - VALID_TIMESTAMP_PAST_SECS;
        let max_ts = now + VALID_TIMESTAMP_FUTURE_SECS;
        if self.timestamp < min_ts || self.timestamp > max_ts {
            return Err(ProfileValidationError::TimestampOutOfRange(self.timestamp));
        }

        Ok(())
    }
}

// ── serde_base64 ──────────────────────────────────────────────────────────────

/// Serde helper: serialize `Vec<u8>` as a base64-encoded string and deserialize back.
mod serde_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn valid_profile() -> NodeProfile {
        NodeProfile {
            display_name: "Alice".to_string(),
            bio: "Sovereign node operator.".to_string(),
            avatar: None,
            verified_identities: vec![],
            timestamp: Utc::now().timestamp(),
        }
    }

    // ── Serde roundtrip ───────────────────────────────────────────────────────

    #[test]
    fn node_profile_roundtrip_minimal() {
        let p = NodeProfile {
            display_name: "Bob".to_string(),
            bio: String::new(),
            avatar: None,
            verified_identities: vec![],
            timestamp: Utc::now().timestamp(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: NodeProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn node_profile_roundtrip_with_inline_avatar() {
        let p = NodeProfile {
            display_name: "Carol".to_string(),
            bio: "Has an avatar.".to_string(),
            avatar: Some(AvatarRef::Inline(AvatarInline {
                data: vec![0xFF, 0xD8, 0xFF, 0xE0], // JPEG magic bytes
                mime_type: "image/jpeg".to_string(),
            })),
            verified_identities: vec![],
            timestamp: Utc::now().timestamp(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: NodeProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn node_profile_roundtrip_with_hashed_avatar() {
        let p = NodeProfile {
            display_name: "Dave".to_string(),
            bio: String::new(),
            avatar: Some(AvatarRef::Hashed(AvatarHashed {
                hash: "a".repeat(64),
                size_bytes: 65_536,
                mime_type: "image/png".to_string(),
            })),
            verified_identities: vec![],
            timestamp: Utc::now().timestamp(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: NodeProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn node_profile_roundtrip_with_verified_identities() {
        let p = NodeProfile {
            display_name: "Eve".to_string(),
            bio: "Multi-platform identity.".to_string(),
            avatar: None,
            verified_identities: vec![
                VerifiedIdentity {
                    platform: "github".to_string(),
                    handle: "eve-dev".to_string(),
                    proof: "https://gist.github.com/eve-dev/abc123".to_string(),
                },
                VerifiedIdentity {
                    platform: "keybase".to_string(),
                    handle: "eve".to_string(),
                    proof: "https://keybase.io/eve".to_string(),
                },
            ],
            timestamp: Utc::now().timestamp(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: NodeProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, decoded);
        assert_eq!(decoded.verified_identities.len(), 2);
    }

    #[test]
    fn node_profile_defaults_on_deserialize() {
        // bio, avatar, verified_identities have serde(default)
        let json = r#"{"display_name":"Frank","timestamp":1700000000}"#;
        let p: NodeProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.display_name, "Frank");
        assert_eq!(p.bio, "");
        assert!(p.avatar.is_none());
        assert!(p.verified_identities.is_empty());
    }

    #[test]
    fn avatar_ref_inline_base64_roundtrip() {
        let inline = AvatarInline {
            data: (0u8..=255).collect(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_string(&inline).unwrap();
        // Verify the data field serializes as a base64 string, not an array
        assert!(json.contains('"'), "data field should be a quoted base64 string");
        let decoded: AvatarInline = serde_json::from_str(&json).unwrap();
        assert_eq!(inline, decoded);
    }

    #[test]
    fn avatar_ref_tag_discrimination() {
        let inline = AvatarRef::Inline(AvatarInline {
            data: vec![1, 2, 3],
            mime_type: "image/png".to_string(),
        });
        let hashed = AvatarRef::Hashed(AvatarHashed {
            hash: "b".repeat(64),
            size_bytes: 1024,
            mime_type: "image/webp".to_string(),
        });
        let inline_json = serde_json::to_string(&inline).unwrap();
        let hashed_json = serde_json::to_string(&hashed).unwrap();
        assert!(inline_json.contains(r#""type":"inline""#));
        assert!(hashed_json.contains(r#""type":"hashed""#));
        let decoded_inline: AvatarRef = serde_json::from_str(&inline_json).unwrap();
        let decoded_hashed: AvatarRef = serde_json::from_str(&hashed_json).unwrap();
        assert_eq!(inline, decoded_inline);
        assert_eq!(hashed, decoded_hashed);
    }

    // ── Validation — Rule 2: bidi overrides ───────────────────────────────────

    #[test]
    fn validate_rejects_bidi_in_name() {
        let mut p = valid_profile();
        p.display_name = "Alice\u{202E}".to_string(); // RIGHT-TO-LEFT OVERRIDE
        assert_eq!(p.validate(), Err(ProfileValidationError::NameBidiOverride));
    }

    #[test]
    fn validate_rejects_rtl_embedding_in_name() {
        let mut p = valid_profile();
        p.display_name = "\u{202B}Alice".to_string(); // RIGHT-TO-LEFT EMBEDDING
        assert_eq!(p.validate(), Err(ProfileValidationError::NameBidiOverride));
    }

    #[test]
    fn validate_rejects_bidi_in_bio() {
        let mut p = valid_profile();
        p.bio = "Normal text \u{202A} injected".to_string(); // LEFT-TO-RIGHT EMBEDDING
        assert_eq!(p.validate(), Err(ProfileValidationError::BioBidiOverride));
    }

    // ── Validation — Rule 3: name length ──────────────────────────────────────

    #[test]
    fn validate_accepts_name_at_limit() {
        let mut p = valid_profile();
        p.display_name = "A".repeat(48);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_rejects_name_over_limit() {
        let mut p = valid_profile();
        p.display_name = "A".repeat(49);
        assert_eq!(p.validate(), Err(ProfileValidationError::NameTooLong(49)));
    }

    #[test]
    fn validate_counts_unicode_scalar_values_not_bytes() {
        // "é" as precomposed NFC is 1 char (2 bytes UTF-8)
        let mut p = valid_profile();
        p.display_name = "\u{00E9}".repeat(48); // 48 × é (each 2 bytes, 1 char)
        assert!(p.validate().is_ok(), "48 NFC chars must be accepted");

        let mut p2 = valid_profile();
        p2.display_name = "\u{00E9}".repeat(49);
        assert_eq!(p2.validate(), Err(ProfileValidationError::NameTooLong(49)));
    }

    // ── Validation — Rule 6: bio length ───────────────────────────────────────

    #[test]
    fn validate_accepts_bio_at_limit() {
        let mut p = valid_profile();
        p.bio = "B".repeat(280);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bio_over_limit() {
        let mut p = valid_profile();
        p.bio = "B".repeat(281);
        assert_eq!(p.validate(), Err(ProfileValidationError::BioTooLong(281)));
    }

    // ── Validation — Rule 7: inline avatar size ───────────────────────────────

    #[test]
    fn validate_accepts_inline_avatar_at_limit() {
        let mut p = valid_profile();
        p.avatar = Some(AvatarRef::Inline(AvatarInline {
            data: vec![0u8; 8_192],
            mime_type: "image/png".to_string(),
        }));
        // May fail rule 9 (payload size) due to base64 overhead — that is expected.
        let result = p.validate();
        assert!(
            result.is_ok() || matches!(result, Err(ProfileValidationError::PayloadTooLarge(_))),
            "should pass rule 7 even if rule 9 triggers: {result:?}"
        );
    }

    #[test]
    fn validate_rejects_inline_avatar_too_large() {
        let mut p = valid_profile();
        p.avatar = Some(AvatarRef::Inline(AvatarInline {
            data: vec![0u8; 8_193],
            mime_type: "image/png".to_string(),
        }));
        assert_eq!(
            p.validate(),
            Err(ProfileValidationError::InlineAvatarTooLarge(8_193))
        );
    }

    // ── Validation — Rule 8: hashed avatar declared size ─────────────────────

    #[test]
    fn validate_accepts_hashed_avatar_at_limit() {
        let mut p = valid_profile();
        p.avatar = Some(AvatarRef::Hashed(AvatarHashed {
            hash: "c".repeat(64),
            size_bytes: 524_288,
            mime_type: "image/jpeg".to_string(),
        }));
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_rejects_hashed_avatar_too_large() {
        let mut p = valid_profile();
        p.avatar = Some(AvatarRef::Hashed(AvatarHashed {
            hash: "c".repeat(64),
            size_bytes: 524_289,
            mime_type: "image/jpeg".to_string(),
        }));
        assert_eq!(
            p.validate(),
            Err(ProfileValidationError::HashedAvatarTooLarge(524_289))
        );
    }

    // ── Validation — Rule 9: total payload size ───────────────────────────────

    #[test]
    fn validate_rejects_oversized_payload() {
        let mut p = valid_profile();
        // Stuff verified_identities with data until the payload exceeds 12 KiB
        p.verified_identities = (0..200)
            .map(|i| VerifiedIdentity {
                platform: "github".to_string(),
                handle: format!("user{i:04}"),
                proof: "https://example.com/".to_string() + &"x".repeat(50),
            })
            .collect();
        assert!(matches!(
            p.validate(),
            Err(ProfileValidationError::PayloadTooLarge(_))
        ));
    }

    // ── Validation — Rule 10: timestamp range ────────────────────────────────

    #[test]
    fn validate_rejects_timestamp_too_old() {
        let mut p = valid_profile();
        // 1 year + 1 second in the past
        p.timestamp = Utc::now().timestamp() - VALID_TIMESTAMP_PAST_SECS - 1;
        assert!(matches!(
            p.validate(),
            Err(ProfileValidationError::TimestampOutOfRange(_))
        ));
    }

    #[test]
    fn validate_rejects_timestamp_too_far_future() {
        let mut p = valid_profile();
        // 5 minutes + 1 second in the future
        p.timestamp = Utc::now().timestamp() + VALID_TIMESTAMP_FUTURE_SECS + 1;
        assert!(matches!(
            p.validate(),
            Err(ProfileValidationError::TimestampOutOfRange(_))
        ));
    }

    #[test]
    fn validate_accepts_current_timestamp() {
        let mut p = valid_profile();
        p.timestamp = Utc::now().timestamp();
        assert!(p.validate().is_ok());
    }

    // ── Validation — NFC normalization (rules 1 & 4) ─────────────────────────

    #[test]
    fn validate_nfc_normalizes_name_in_place() {
        // "é" in decomposed NFD form: 'e' + combining acute accent (2 code points)
        let nfd_e = "e\u{0301}"; // NFD
        let nfc_e = "\u{00E9}"; // NFC (precomposed)

        let mut p = valid_profile();
        p.display_name = nfd_e.to_string();
        p.validate().unwrap();
        assert_eq!(
            p.display_name, nfc_e,
            "display_name should be NFC-normalized after validate()"
        );
    }

    #[test]
    fn validate_nfc_normalizes_bio_in_place() {
        let nfd_e = "e\u{0301}"; // NFD 'é'
        let nfc_e = "\u{00E9}"; // NFC 'é'

        let mut p = valid_profile();
        p.bio = format!("Bio with {nfd_e} character.");
        p.validate().unwrap();
        assert!(
            p.bio.contains(nfc_e),
            "bio should contain NFC-normalized text after validate()"
        );
    }

    // ── KIND_PROFILE constant ─────────────────────────────────────────────────

    #[test]
    fn kind_profile_is_103() {
        assert_eq!(KIND_PROFILE, 103);
    }

    #[test]
    fn kind_profile_is_structured_data() {
        use crate::kind::KindCategory;
        assert_eq!(
            KindCategory::from_kind(KIND_PROFILE),
            KindCategory::StructuredData
        );
    }
}
