//! Signed front-door cards (doorstep, free to carry).
//!
//! A front-door card is a self-contained, node-signed document the owner
//! publishes once. Anyone may cache, host or share it (link / QR). Reading it
//! never contacts the owner's node. **Knocking** uses the existing paid first
//! contact path; porch pages are a later paid act.
//!
//! # Wire form
//!
//! ```text
//! bitsov://front-door#<base64url-nopad(JSON card including sig)>
//! ```
//!
//! Whole card ≤ [`MAX_CARD_BYTES`] (16 KiB). Ed25519 over
//! `BLAKE3(DOMAIN_V1 || canonical JSON without sig)`.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::NodeIdentity;
use crate::introduction::{Reach, NETWORKS};
use crate::types::NodeId;

/// Domain-separation tag for front-door signatures.
pub const DOMAIN_V1: &[u8] = b"bitsov-front-door/v1\0";
/// Format version.
pub const VERSION: u8 = 1;
/// Link prefix.
pub const LINK_PREFIX: &str = "bitsov://front-door#";
/// Default and maximum lifetime (7 days).
pub const LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// Clock skew on `issued_at`.
pub const MAX_SKEW_SECS: u64 = 60;
/// Whole card including signature (design: 16 KiB).
pub const MAX_CARD_BYTES: usize = 16 * 1024;
pub const MAX_ENDPOINT_LEN: usize = 255;
pub const MAX_DISPLAY_NAME: usize = 48;
pub const MAX_TAGLINE: usize = 80;
pub const MAX_ABOUT: usize = 280;
pub const MAX_AVATAR_INLINE: usize = 8 * 1024;
pub const MAX_MEDIA: usize = 12;
pub const MAX_THUMB_INLINE: usize = 4 * 1024;
pub const MAX_MEDIA_TITLE: usize = 64;
pub const MAX_LINKS: usize = 5;
pub const MAX_SITE_TITLES: usize = 20;
pub const MAX_PATH_LEN: usize = 128;
pub const MAX_MIME_LEN: usize = 64;
pub const MAX_LINK_LABEL: usize = 64;
pub const MAX_LINK_URL: usize = 512;
pub const HASH_HEX_LEN: usize = 64;

/// Errors from building, decoding or verifying a front-door card.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrontDoorError {
    #[error("front-door card is too large ({0} bytes, max {MAX_CARD_BYTES})")]
    TooLarge(usize),
    #[error("not a front-door card: {0}")]
    Malformed(String),
    #[error("unsupported front-door version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown network {0:?}")]
    UnknownNetwork(String),
    #[error("front-door is for {card}, this node runs {ours}")]
    WrongNetwork { card: String, ours: String },
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("front-door expired at {0}")]
    Expired(u64),
    #[error("front-door is issued in the future")]
    NotYetValid,
    #[error("front-door lives longer than {LIFETIME_SECS} s")]
    LifetimeTooLong,
    #[error("invalid node key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("field too long: {0}")]
    FieldTooLong(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("reach does not match endpoint: {0}")]
    ReachMismatch(&'static str),
    #[error("seq must increase when updating")]
    SeqNotMonotonic,
}

/// Person or company badge on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    Person,
    Company,
}

/// Avatar: small inline bytes, or a content hash for porch fetch later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Avatar {
    /// Base64 of inline image bytes (≤ 8 KiB), preferred for the doorstep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_b64: Option<String>,
    /// Blake3 hash hex of a larger asset (≤ 512 KiB), fetched on the porch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

/// Snapshot prices (display only; receptor quote binds on knock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorPrices {
    pub admission_msat: u64,
    pub message_msat: u64,
    #[serde(default)]
    pub page_msat: u64,
    #[serde(default)]
    pub price_epoch: u64,
}

/// Profile block on the card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorProfile {
    pub kind: ProfileKind,
    pub display_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub about: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Avatar>,
}

/// CV pointer (markdown page on the porch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorCv {
    pub path: String,
    pub hash: String,
    pub size: u64,
}

/// Media thumbnail strip entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorMedia {
    pub hash: String,
    pub size: u64,
    pub mime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumb_b64: Option<String>,
    #[serde(default)]
    pub title: String,
}

/// Site summary from the owner's pages/.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorSite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_path: Option<String>,
    #[serde(default)]
    pub page_count: u32,
    #[serde(default)]
    pub titles: Vec<String>,
}

/// Optional plain URL (never auto-fetched).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorLink {
    pub label: String,
    pub url: String,
}

/// Signed FrontDoorCard v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorCard {
    pub v: u8,
    pub network: String,
    pub node_id: String,
    pub endpoint: String,
    pub reach: Reach,
    /// Monotonic version; higher `seq` replaces lower when caching.
    pub seq: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub prices: FrontDoorPrices,
    pub profile: FrontDoorProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<FrontDoorCv>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<FrontDoorMedia>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<FrontDoorSite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<FrontDoorLink>,
    /// Ed25519 signature over `BLAKE3(DOMAIN_V1 || canonical JSON without sig)`, hex.
    pub sig: String,
}

/// Owner-supplied fields when creating or updating a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontDoorFields {
    pub network: String,
    pub endpoint: String,
    pub seq: u64,
    pub issued_at: u64,
    pub prices: FrontDoorPrices,
    pub profile: FrontDoorProfile,
    #[serde(default)]
    pub cv: Option<FrontDoorCv>,
    #[serde(default)]
    pub media: Vec<FrontDoorMedia>,
    #[serde(default)]
    pub site: Option<FrontDoorSite>,
    #[serde(default)]
    pub links: Vec<FrontDoorLink>,
}

impl FrontDoorCard {
    /// Sign `fields` with the node identity.
    pub fn issue(identity: &NodeIdentity, fields: FrontDoorFields) -> Result<Self, FrontDoorError> {
        Self::issue_with_key(identity.ed25519_signing_key(), fields)
    }

    pub fn issue_with_key(key: &SigningKey, fields: FrontDoorFields) -> Result<Self, FrontDoorError> {
        let endpoint = fields.endpoint.trim().to_string();
        let reach = reach_of_endpoint(&endpoint)?;
        let mut card = Self {
            v: VERSION,
            network: fields.network,
            node_id: hex::encode(key.verifying_key().to_bytes()),
            endpoint,
            reach,
            seq: fields.seq,
            issued_at: fields.issued_at,
            expires_at: fields.issued_at.saturating_add(LIFETIME_SECS),
            prices: fields.prices,
            profile: fields.profile,
            cv: fields.cv,
            media: fields.media,
            site: fields.site,
            links: fields.links,
            sig: String::new(),
        };
        card.check_shape()?;
        card.sig = hex::encode(key.sign(&card.digest()?).to_bytes());
        card.ensure_size()?;
        Ok(card)
    }

    pub fn node(&self) -> Result<NodeId, FrontDoorError> {
        NodeId::from_hex(&self.node_id).map_err(|_| FrontDoorError::InvalidKey)
    }

    /// Canonical JSON of every field except `sig`, for signing.
    pub fn canonical_json(&self) -> Result<Vec<u8>, FrontDoorError> {
        #[derive(Serialize)]
        struct Body<'a> {
            v: u8,
            network: &'a str,
            node_id: &'a str,
            endpoint: &'a str,
            reach: Reach,
            seq: u64,
            issued_at: u64,
            expires_at: u64,
            prices: &'a FrontDoorPrices,
            profile: &'a FrontDoorProfile,
            #[serde(skip_serializing_if = "Option::is_none")]
            cv: &'a Option<FrontDoorCv>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            media: &'a Vec<FrontDoorMedia>,
            #[serde(skip_serializing_if = "Option::is_none")]
            site: &'a Option<FrontDoorSite>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            links: &'a Vec<FrontDoorLink>,
        }
        let body = Body {
            v: self.v,
            network: &self.network,
            node_id: &self.node_id,
            endpoint: &self.endpoint,
            reach: self.reach,
            seq: self.seq,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            prices: &self.prices,
            profile: &self.profile,
            cv: &self.cv,
            media: &self.media,
            site: &self.site,
            links: &self.links,
        };
        serde_json::to_vec(&body).map_err(|e| FrontDoorError::Malformed(e.to_string()))
    }

    fn digest(&self) -> Result<[u8; 32], FrontDoorError> {
        let mut buf = Vec::with_capacity(DOMAIN_V1.len() + 256);
        buf.extend_from_slice(DOMAIN_V1);
        buf.extend_from_slice(&self.canonical_json()?);
        Ok(*blake3::hash(&buf).as_bytes())
    }

    fn ensure_size(&self) -> Result<(), FrontDoorError> {
        let encoded = serde_json::to_vec(self).map_err(|e| FrontDoorError::Malformed(e.to_string()))?;
        if encoded.len() > MAX_CARD_BYTES {
            return Err(FrontDoorError::TooLarge(encoded.len()));
        }
        Ok(())
    }

    fn check_shape(&self) -> Result<(), FrontDoorError> {
        if self.v != VERSION {
            return Err(FrontDoorError::UnsupportedVersion(self.v));
        }
        if !NETWORKS.contains(&self.network.as_str()) {
            return Err(FrontDoorError::UnknownNetwork(self.network.clone()));
        }
        if self.endpoint.is_empty() || self.endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(FrontDoorError::InvalidEndpoint("length".into()));
        }
        let literal = reach_of_endpoint(&self.endpoint)?;
        if self.reach == Reach::Public && literal == Reach::Local {
            return Err(FrontDoorError::ReachMismatch("public"));
        }
        if self.expires_at <= self.issued_at || self.expires_at - self.issued_at > LIFETIME_SECS {
            return Err(FrontDoorError::LifetimeTooLong);
        }
        if self.profile.display_name.is_empty() || self.profile.display_name.len() > MAX_DISPLAY_NAME {
            return Err(FrontDoorError::FieldTooLong("display_name"));
        }
        if self.profile.tagline.len() > MAX_TAGLINE {
            return Err(FrontDoorError::FieldTooLong("tagline"));
        }
        if self.profile.about.len() > MAX_ABOUT {
            return Err(FrontDoorError::FieldTooLong("about"));
        }
        if let Some(av) = &self.profile.avatar {
            if let Some(b64) = &av.inline_b64 {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| FrontDoorError::Malformed("avatar inline_b64".into()))?;
                if raw.len() > MAX_AVATAR_INLINE {
                    return Err(FrontDoorError::FieldTooLong("avatar.inline"));
                }
            }
            if let Some(h) = &av.hash {
                check_hash_hex(h, "avatar.hash")?;
            }
            if let Some(m) = &av.mime {
                check_mime(m, "avatar.mime")?;
            }
        }
        if self.media.len() > MAX_MEDIA {
            return Err(FrontDoorError::FieldTooLong("media"));
        }
        for m in &self.media {
            check_hash_hex(&m.hash, "media.hash")?;
            check_mime(&m.mime, "media.mime")?;
            if m.title.len() > MAX_MEDIA_TITLE {
                return Err(FrontDoorError::FieldTooLong("media.title"));
            }
            if let Some(t) = &m.thumb_b64 {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(t)
                    .map_err(|_| FrontDoorError::Malformed("media.thumb_b64".into()))?;
                if raw.len() > MAX_THUMB_INLINE {
                    return Err(FrontDoorError::FieldTooLong("media.thumb"));
                }
            }
        }
        if self.links.len() > MAX_LINKS {
            return Err(FrontDoorError::FieldTooLong("links"));
        }
        for link in &self.links {
            if link.label.is_empty() || link.label.len() > MAX_LINK_LABEL {
                return Err(FrontDoorError::FieldTooLong("links.label"));
            }
            check_link_url(&link.url)?;
        }
        if let Some(cv) = &self.cv {
            check_safe_path(&cv.path, "cv.path")?;
            check_hash_hex(&cv.hash, "cv.hash")?;
        }
        if let Some(site) = &self.site {
            if site.titles.len() > MAX_SITE_TITLES {
                return Err(FrontDoorError::FieldTooLong("site.titles"));
            }
            for t in &site.titles {
                if t.len() > MAX_MEDIA_TITLE {
                    return Err(FrontDoorError::FieldTooLong("site.titles"));
                }
            }
            if let Some(p) = &site.index_path {
                check_safe_path(p, "site.index_path")?;
            }
            if let Some(h) = &site.manifest_hash {
                check_hash_hex(h, "site.manifest_hash")?;
            }
        }
        Ok(())
    }

    /// Shape, size and Ed25519 signature — no clock or network checks.
    ///
    /// Callers that want to render an expired card "as of <date>" must still
    /// pass this; expiry is never a substitute for a valid signature.
    pub fn verify_signature(&self) -> Result<(), FrontDoorError> {
        self.check_shape()?;
        self.ensure_size()?;
        let key = decode_fixed::<32>(&self.node_id).ok_or(FrontDoorError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| FrontDoorError::InvalidKey)?;
        let sig = decode_fixed::<64>(&self.sig).ok_or(FrontDoorError::InvalidSignature)?;
        key.verify_strict(&self.digest()?, &Signature::from_bytes(&sig))
            .map_err(|_| FrontDoorError::InvalidSignature)
    }

    /// Verify signature first, then network and expiry.
    pub fn verify(&self, now_unix: u64, network: &str) -> Result<(), FrontDoorError> {
        self.verify_signature()?;
        if self.network != network {
            return Err(FrontDoorError::WrongNetwork {
                card: self.network.clone(),
                ours: network.into(),
            });
        }
        if self.issued_at > now_unix.saturating_add(MAX_SKEW_SECS) {
            return Err(FrontDoorError::NotYetValid);
        }
        if self.expires_at <= now_unix {
            return Err(FrontDoorError::Expired(self.expires_at));
        }
        Ok(())
    }

    /// `bitsov://front-door#<base64url(JSON)>` for QR / share.
    pub fn to_link(&self) -> Result<String, FrontDoorError> {
        self.ensure_size()?;
        let json = serde_json::to_vec(self).map_err(|e| FrontDoorError::Malformed(e.to_string()))?;
        if json.len() > MAX_CARD_BYTES {
            return Err(FrontDoorError::TooLarge(json.len()));
        }
        Ok(format!(
            "{LINK_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }

    /// Parse a link, fragment, or JSON card.
    pub fn parse(text: &str) -> Result<Self, FrontDoorError> {
        let text = text.trim();
        if text.len() > MAX_CARD_BYTES * 2 {
            return Err(FrontDoorError::TooLarge(text.len()));
        }
        let payload = if let Some(rest) = text.strip_prefix(LINK_PREFIX) {
            rest
        } else if text.starts_with('{') {
            let card: Self = serde_json::from_str(text)
                .map_err(|e| FrontDoorError::Malformed(e.to_string()))?;
            card.check_shape()?;
            card.ensure_size()?;
            return Ok(card);
        } else {
            text
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
            .map_err(|_| FrontDoorError::Malformed("base64".into()))?;
        if bytes.len() > MAX_CARD_BYTES {
            return Err(FrontDoorError::TooLarge(bytes.len()));
        }
        let card: Self = serde_json::from_slice(&bytes)
            .map_err(|e| FrontDoorError::Malformed(e.to_string()))?;
        card.check_shape()?;
        card.ensure_size()?;
        Ok(card)
    }
}

fn reach_of_endpoint(endpoint: &str) -> Result<Reach, FrontDoorError> {
    crate::introduction::reach_of(endpoint).map_err(|e| FrontDoorError::InvalidEndpoint(e.to_string()))
}

fn decode_fixed<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn check_hash_hex(value: &str, field: &'static str) -> Result<(), FrontDoorError> {
    if value.len() != HASH_HEX_LEN || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FrontDoorError::InvalidField(field));
    }
    Ok(())
}

fn check_mime(value: &str, field: &'static str) -> Result<(), FrontDoorError> {
    if value.is_empty() || value.len() > MAX_MIME_LEN || value.chars().any(|c| c.is_control()) {
        return Err(FrontDoorError::InvalidField(field));
    }
    Ok(())
}

fn check_safe_path(path: &str, field: &'static str) -> Result<(), FrontDoorError> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(FrontDoorError::FieldTooLong(field));
    }
    if path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || path.contains('\0')
        || path.contains('/')
    {
        return Err(FrontDoorError::InvalidField(field));
    }
    Ok(())
}

fn check_link_url(url: &str) -> Result<(), FrontDoorError> {
    if url.len() > MAX_LINK_URL {
        return Err(FrontDoorError::FieldTooLong("links.url"));
    }
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(FrontDoorError::InvalidField("links.url"));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(FrontDoorError::InvalidField("links.url"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn fields(seq: u64, issued: u64) -> FrontDoorFields {
        FrontDoorFields {
            network: "regtest".into(),
            endpoint: "node.example.org:9000".into(),
            seq,
            issued_at: issued,
            prices: FrontDoorPrices {
                admission_msat: 100_000,
                message_msat: 10_000,
                page_msat: 1_000,
                price_epoch: 0,
            },
            profile: FrontDoorProfile {
                kind: ProfileKind::Person,
                display_name: "Maya".into(),
                tagline: "Build in the open".into(),
                about: "Pilot peer.".into(),
                avatar: None,
            },
            cv: None,
            media: vec![],
            site: None,
            links: vec![],
        }
    }

    #[test]
    fn issue_verify_and_link_round_trip() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        card.verify(now + 10, "regtest").unwrap();
        let link = card.to_link().unwrap();
        assert!(link.starts_with(LINK_PREFIX));
        let parsed = FrontDoorCard::parse(&link).unwrap();
        assert_eq!(parsed, card);
        parsed.verify(now + 10, "regtest").unwrap();
    }

    #[test]
    fn expired_card_fails_verify() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        assert!(matches!(
            card.verify(now + LIFETIME_SECS + 1, "regtest"),
            Err(FrontDoorError::Expired(_))
        ));
    }

    #[test]
    fn wrong_network_fails() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        assert!(matches!(
            card.verify(now + 1, "bitcoin"),
            Err(FrontDoorError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn oversized_about_refused() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let mut f = fields(1, 1_700_000_000);
        f.profile.about = "x".repeat(MAX_ABOUT + 1);
        assert!(matches!(
            FrontDoorCard::issue(&id, f),
            Err(FrontDoorError::FieldTooLong("about"))
        ));
    }

    #[test]
    fn json_paste_parses() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let card = FrontDoorCard::issue(&id, fields(2, 1_700_000_000)).unwrap();
        let json = serde_json::to_string(&card).unwrap();
        let parsed = FrontDoorCard::parse(&json).unwrap();
        assert_eq!(parsed.seq, 2);
    }

    #[test]
    fn public_reach_with_loopback_refused() {
        use ed25519_dalek::Signer;
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let mut card = FrontDoorCard::issue(&id, fields(1, 1_700_000_000)).unwrap();
        card.endpoint = "127.0.0.1:9000".into();
        card.reach = Reach::Public;
        card.sig = hex::encode(
            id.ed25519_signing_key()
                .sign(&card.digest().unwrap())
                .to_bytes(),
        );
        assert_eq!(
            card.verify_signature(),
            Err(FrontDoorError::ReachMismatch("public"))
        );
    }

    #[test]
    fn path_traversal_refused() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let mut f = fields(1, 1_700_000_000);
        f.cv = Some(FrontDoorCv {
            path: "../secret.md".into(),
            hash: "ab".repeat(32),
            size: 10,
        });
        assert!(matches!(
            FrontDoorCard::issue(&id, f),
            Err(FrontDoorError::InvalidField("cv.path"))
        ));
    }

    #[test]
    fn unsigned_expired_fails_signature_not_expiry() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let mut card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        card.sig = "00".repeat(64);
        // Even when "expired", a forged sig must fail as InvalidSignature.
        assert_eq!(
            card.verify(now + LIFETIME_SECS + 1, "regtest"),
            Err(FrontDoorError::InvalidSignature)
        );
    }

    #[test]
    fn introduction_domain_sig_does_not_verify_front_door() {
        use ed25519_dalek::Signer;
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let mut card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(crate::introduction::DOMAIN_V1);
        buf.extend_from_slice(&card.canonical_json().unwrap());
        let digest = *blake3::hash(&buf).as_bytes();
        card.sig = hex::encode(id.ed25519_signing_key().sign(&digest).to_bytes());
        assert_eq!(
            card.verify_signature(),
            Err(FrontDoorError::InvalidSignature)
        );
    }

    #[test]
    fn front_door_domain_sig_does_not_verify_introduction() {
        use ed25519_dalek::Signer;
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let intro = crate::introduction::Introduction::issue(
            &id,
            crate::introduction::IntroductionFields {
                network: "regtest".into(),
                endpoint: "node.example.org:9000".into(),
                admission_msat: 1000,
                message_msat: 1000,
                price_epoch: 0,
                issued_at: now,
                intro_id: [7u8; 16],
            },
        )
        .unwrap();
        // Re-sign the introduction payload under the front-door domain tag.
        let mut body = intro.canonical_bytes().unwrap();
        body.drain(..crate::introduction::DOMAIN_V1.len());
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_V1);
        buf.extend_from_slice(&body);
        let digest = *blake3::hash(&buf).as_bytes();
        let mut forged = intro.clone();
        forged.sig = hex::encode(id.ed25519_signing_key().sign(&digest).to_bytes());
        assert!(forged.verify(now + 1, "regtest").is_err());
    }

    #[test]
    fn expired_but_signed_still_has_valid_signature() {
        let id = NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
        let now = 1_700_000_000u64;
        let card = FrontDoorCard::issue(&id, fields(1, now)).unwrap();
        card.verify_signature().unwrap();
        assert!(matches!(
            card.verify(now + LIFETIME_SECS + 1, "regtest"),
            Err(FrontDoorError::Expired(_))
        ));
    }
}
