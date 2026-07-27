//! Peer invitation tokens — shareable, self-verifying invite links.
//!
//! An invite token encodes a node's identity (Ed25519 pubkey), network address,
//! optional label, and expiry — all signed by the inviting node's Ed25519 key.
//! Recipients can verify the token's authenticity without contacting the inviter.
//!
//! # Format
//!
//! ```text
//! konsensus://invite/<base58(payload || signature)>
//! ```
//!
//! Where `payload` is:
//! - `node_id` (32 bytes) — Ed25519 public key
//! - `addr_len` (1 byte) — length of address string
//! - `addr` (variable) — network address (host:port), UTF-8
//! - `label_len` (1 byte) — length of optional label
//! - `label` (variable) — human-readable label, UTF-8
//! - `expiry` (8 bytes, u64 BE) — Unix timestamp in seconds, 0 = no expiry
//!
//! And `signature` is 64 bytes (Ed25519 over `payload`).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::NodeIdentity;
use crate::types::NodeId;

mod serde_hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

mod serde_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod serde_hex_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

/// Domain-separation tag mixed into BitSovInvite canonical bytes.
/// Prevents cross-protocol signature reuse if the same identity key is ever
/// used to sign a different payload structure. Per ADR-029.
const BITSOV_INVITE_DOMAIN_V1: &[u8] = b"bitsov-invite-v1\0";
const BITSOV_INVITE_DOMAIN_V2: &[u8] = b"bitsov-invite/v2\0";

/// Currently supported BitSovInvite format version.
/// `verify()` accepts v1 for already-issued invites and v2 for new issuance.
pub const SUPPORTED_INVITE_VERSION: u8 = 2;
const LEGACY_INVITE_VERSION: u8 = 1;

/// URI scheme prefix for invite links.
const INVITE_PREFIX: &str = "konsensus://invite/";

/// Maximum address length (255 bytes, fits in u8).
const MAX_ADDR_LEN: usize = 255;

/// Maximum label length (255 bytes, fits in u8).
const MAX_LABEL_LEN: usize = 255;

/// Errors from invite token operations.
#[derive(Debug, Error)]
pub enum InviteError {
    /// Address too long.
    #[error("address too long: {0} bytes (max {MAX_ADDR_LEN})")]
    AddressTooLong(usize),

    /// Label too long.
    #[error("label too long: {0} bytes (max {MAX_LABEL_LEN})")]
    LabelTooLong(usize),

    /// Address is empty.
    #[error("address cannot be empty")]
    EmptyAddress,

    /// Token is too short to contain the required fields.
    #[error("token too short: {0} bytes")]
    TooShort(usize),

    /// Base58 decoding failed.
    #[error("invalid base58: {0}")]
    Base58(String),

    /// Invalid UTF-8 in address or label.
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(String),

    /// Ed25519 signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Token has expired.
    #[error("token expired at {0}")]
    Expired(u64),

    /// Invalid invite URI format.
    #[error("invalid invite URI: {0}")]
    InvalidUri(String),

    /// Inviter pubkey is not a valid Ed25519 public key.
    #[error("invalid inviter pubkey")]
    InvalidInviterPubkey,

    /// Invite has expired.
    #[error("invite expired at {expiry_unix} (now {now_unix})")]
    InviteExpired { expiry_unix: u64, now_unix: u64 },

    /// Invite format version is not supported by this node.
    #[error("unsupported invite version: {0} (supported: 1..={SUPPORTED_INVITE_VERSION})")]
    UnsupportedVersion(u8),
}

/// Signed invite used by BitSov onboarding flows.
///
/// Wire format: every byte array (`inviter_pubkey`, `invitee_pubkey`, `nonce`,
/// `signature`) serializes as a lowercase hex string for cross-language
/// interop. Per ADR-029 amendment 2026-05-11 (uniform hex encoding).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitSovInvite {
    /// Invite format version.
    pub version: u8,
    /// Inviter Ed25519 public key bytes.
    #[serde(with = "serde_hex_32")]
    pub inviter_pubkey: [u8; 32],
    /// Invitee Ed25519 public key bytes.
    #[serde(with = "serde_hex_32")]
    pub invitee_pubkey: [u8; 32],
    /// Expiry timestamp (Unix seconds).
    pub expiry_unix: u64,
    /// Optional channel sizing hint in sats.
    pub channel_size_hint_sats: Option<u32>,
    /// Inviter's dialable network address for the first connection.
    #[serde(default)]
    pub addr: String,
    /// Inviter-signed upper bound for channel-open fee rate.
    #[serde(default)]
    pub max_fee_rate_sat_per_vb: Option<u32>,
    /// Inviter-signed expiry for the implicit channel-open authorization.
    #[serde(default)]
    pub channel_open_intent_expiry_unix: Option<u64>,
    /// Per-invite nonce.
    #[serde(with = "serde_hex_16")]
    pub nonce: [u8; 16],
    /// Ed25519 signature over canonical bytes.
    #[serde(with = "serde_hex_64")]
    pub signature: [u8; 64],
}

/// Unsigned BitSov invite payload.
///
/// This type carries all signed fields except the signature so invites can be
/// constructed first and then atomically signed into a `BitSovInvite`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedBitSovInvite {
    /// Invite format version.
    pub version: u8,
    /// Inviter Ed25519 public key bytes.
    #[serde(with = "serde_hex_32")]
    pub inviter_pubkey: [u8; 32],
    /// Invitee Ed25519 public key bytes.
    #[serde(with = "serde_hex_32")]
    pub invitee_pubkey: [u8; 32],
    /// Expiry timestamp (Unix seconds).
    pub expiry_unix: u64,
    /// Optional channel sizing hint in sats.
    pub channel_size_hint_sats: Option<u32>,
    /// Inviter's dialable network address for the first connection.
    #[serde(default)]
    pub addr: String,
    /// Inviter-signed upper bound for channel-open fee rate.
    #[serde(default)]
    pub max_fee_rate_sat_per_vb: Option<u32>,
    /// Inviter-signed expiry for the implicit channel-open authorization.
    #[serde(default)]
    pub channel_open_intent_expiry_unix: Option<u64>,
    /// Per-invite nonce.
    #[serde(with = "serde_hex_16")]
    pub nonce: [u8; 16],
}

impl BitSovInvite {
    fn domain_tag(version: u8) -> Result<&'static [u8], InviteError> {
        match version {
            LEGACY_INVITE_VERSION => Ok(BITSOV_INVITE_DOMAIN_V1),
            SUPPORTED_INVITE_VERSION => Ok(BITSOV_INVITE_DOMAIN_V2),
            _ => Err(InviteError::UnsupportedVersion(version)),
        }
    }

    fn append_option_u32(payload: &mut Vec<u8>, value: Option<u32>) {
        match value {
            Some(value) => {
                payload.push(1);
                payload.extend_from_slice(&value.to_be_bytes());
            }
            None => payload.push(0),
        }
    }

    fn append_option_u64(payload: &mut Vec<u8>, value: Option<u64>) {
        match value {
            Some(value) => {
                payload.push(1);
                payload.extend_from_slice(&value.to_be_bytes());
            }
            None => payload.push(0),
        }
    }

    /// Returns the BLAKE3 hash over strictly ordered field bytes excluding signature.
    ///
    /// Payload is prefixed with the domain-separation tag `BITSOV_INVITE_DOMAIN_V1`
    /// to prevent cross-protocol signature reuse with any other payload an inviter
    /// might sign. Per ADR-029 amendment 2026-05-11.
    pub fn canonical_bytes(&self) -> Result<[u8; 32], InviteError> {
        let domain_tag = Self::domain_tag(self.version)?;
        if self.version == SUPPORTED_INVITE_VERSION && self.addr.is_empty() {
            return Err(InviteError::EmptyAddress);
        }
        if self.addr.len() > MAX_ADDR_LEN {
            return Err(InviteError::AddressTooLong(self.addr.len()));
        }

        let mut payload = Vec::with_capacity(
            domain_tag.len() + 1 + 32 + 32 + 8 + 1 + 4 + 1 + self.addr.len() + 1 + 4 + 1 + 8 + 16,
        );
        payload.extend_from_slice(domain_tag);
        payload.push(self.version);
        payload.extend_from_slice(&self.inviter_pubkey);
        payload.extend_from_slice(&self.invitee_pubkey);
        payload.extend_from_slice(&self.expiry_unix.to_be_bytes());
        Self::append_option_u32(&mut payload, self.channel_size_hint_sats);
        if self.version == SUPPORTED_INVITE_VERSION {
            payload.push(self.addr.len() as u8);
            payload.extend_from_slice(self.addr.as_bytes());
            Self::append_option_u32(&mut payload, self.max_fee_rate_sat_per_vb);
            Self::append_option_u64(&mut payload, self.channel_open_intent_expiry_unix);
        }
        payload.extend_from_slice(&self.nonce);
        Ok(*blake3::hash(&payload).as_bytes())
    }

    /// Signs an unsigned invite and returns an atomically-constructed signed invite.
    ///
    /// Currently infallible on `ed25519_dalek::SigningKey::sign`; the `Result`
    /// is preserved for future validation (e.g., refusing to sign an
    /// already-expired invite). Callers should not write `.unwrap()` against
    /// this future-facing API.
    pub fn sign(
        unsigned: UnsignedBitSovInvite,
        signing_key: &SigningKey,
    ) -> Result<Self, InviteError> {
        let invite = Self {
            version: unsigned.version,
            inviter_pubkey: unsigned.inviter_pubkey,
            invitee_pubkey: unsigned.invitee_pubkey,
            expiry_unix: unsigned.expiry_unix,
            channel_size_hint_sats: unsigned.channel_size_hint_sats,
            addr: unsigned.addr,
            max_fee_rate_sat_per_vb: unsigned.max_fee_rate_sat_per_vb,
            channel_open_intent_expiry_unix: unsigned.channel_open_intent_expiry_unix,
            nonce: unsigned.nonce,
            signature: [0u8; 64],
        };
        let sig = signing_key.sign(&invite.canonical_bytes()?);
        Ok(Self {
            signature: sig.to_bytes(),
            ..invite
        })
    }

    /// Verifies version, signature, and expiry against a caller-supplied `now_unix`.
    ///
    /// Checks performed (in order):
    /// 1. `version == 1` (currently the only supported format)
    /// 2. `expiry_unix > now_unix` (caller-supplied time)
    /// 3. Signature valid for `canonical_bytes()` under `inviter_pubkey`
    ///
    /// Time is a parameter rather than read from `SystemTime::now()` so that:
    /// (1) the function is deterministically testable without clock mocking,
    /// (2) a misconfigured system clock cannot silently make expired invites
    ///     pass (which would be a fail-OPEN regression of Principle 2). Callers
    ///     pass the current Unix seconds; if their clock is broken, that's a
    ///     caller-level concern.
    ///
    /// What this function does NOT do — caller responsibilities:
    /// - **Invitee matching**: caller must verify `invitee_pubkey` matches the
    ///   accepting node's own identity.
    /// - **Replay protection**: caller must track accepted `nonce` values
    ///   (e.g. in the `accepted_invites` table in ONB3) and reject re-presents.
    ///   This function is intentionally stateless.
    pub fn verify(&self, now_unix: u64) -> Result<(), InviteError> {
        if self.expiry_unix <= now_unix {
            return Err(InviteError::InviteExpired {
                expiry_unix: self.expiry_unix,
                now_unix,
            });
        }

        let verifying_key = VerifyingKey::from_bytes(&self.inviter_pubkey)
            .map_err(|_| InviteError::InvalidInviterPubkey)?;
        let signature = Signature::from_bytes(&self.signature);
        let canonical = self.canonical_bytes()?;
        verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| InviteError::InvalidSignature)
    }
}

/// A parsed, verified invite token.
#[derive(Debug, Clone)]
pub struct InviteToken {
    /// The inviting node's ID (Ed25519 public key hash).
    pub node_id: NodeId,
    /// The inviting node's network address (host:port).
    pub addr: String,
    /// Optional human-readable label for the node.
    pub label: Option<String>,
    /// Expiry timestamp (Unix seconds), 0 = no expiry.
    pub expiry: u64,
}

impl InviteToken {
    /// Generate a signed invite token.
    ///
    /// The token is signed with the node's Ed25519 key, so recipients can
    /// verify it came from the claimed identity without contacting the node.
    pub fn generate(
        identity: &NodeIdentity,
        addr: &str,
        label: Option<&str>,
        expiry: u64,
    ) -> Result<String, InviteError> {
        if addr.is_empty() {
            return Err(InviteError::EmptyAddress);
        }
        if addr.len() > MAX_ADDR_LEN {
            return Err(InviteError::AddressTooLong(addr.len()));
        }
        let label_bytes = label.unwrap_or("");
        if label_bytes.len() > MAX_LABEL_LEN {
            return Err(InviteError::LabelTooLong(label_bytes.len()));
        }

        let payload = Self::build_payload(identity.node_id(), addr, label_bytes, expiry);
        let signature = identity.sign(&payload);

        let mut token_bytes = payload;
        token_bytes.extend_from_slice(&signature.to_bytes());

        Ok(bs58::encode(&token_bytes).into_string())
    }

    /// Generate a full invite URI (`konsensus://invite/<base58>`).
    pub fn generate_uri(
        identity: &NodeIdentity,
        addr: &str,
        label: Option<&str>,
        expiry: u64,
    ) -> Result<String, InviteError> {
        let token = Self::generate(identity, addr, label, expiry)?;
        Ok(format!("{INVITE_PREFIX}{token}"))
    }

    /// Parse and verify an invite token (base58 string).
    ///
    /// Returns the parsed token if the signature is valid and the token
    /// has not expired. Does NOT check whether the node is reachable.
    pub fn parse(token: &str) -> Result<Self, InviteError> {
        let bytes = bs58::decode(token)
            .into_vec()
            .map_err(|e| InviteError::Base58(e.to_string()))?;

        Self::parse_bytes(&bytes)
    }

    /// Parse and verify an invite URI (`konsensus://invite/<base58>`).
    pub fn parse_uri(uri: &str) -> Result<Self, InviteError> {
        let token = uri
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| InviteError::InvalidUri(format!("must start with {INVITE_PREFIX}")))?;

        Self::parse(token)
    }

    /// Parse raw token bytes (after base58 decoding).
    fn parse_bytes(bytes: &[u8]) -> Result<Self, InviteError> {
        // Minimum: 32 (node_id) + 1 (addr_len) + 1 (label_len) + 8 (expiry) + 64 (sig) = 106
        const MIN_LEN: usize = 32 + 1 + 1 + 8 + 64;
        if bytes.len() < MIN_LEN {
            return Err(InviteError::TooShort(bytes.len()));
        }

        let mut cursor = 0;

        // node_id (32 bytes)
        let node_id_bytes: [u8; 32] = bytes[cursor..cursor + 32]
            .try_into()
            .map_err(|_| InviteError::TooShort(bytes.len()))?;
        cursor += 32;

        // addr_len (1 byte) + addr
        let addr_len = bytes[cursor] as usize;
        cursor += 1;
        if cursor + addr_len > bytes.len() - 64 {
            return Err(InviteError::TooShort(bytes.len()));
        }
        let addr = std::str::from_utf8(&bytes[cursor..cursor + addr_len])
            .map_err(|e| InviteError::InvalidUtf8(e.to_string()))?
            .to_string();
        cursor += addr_len;

        // label_len (1 byte) + label
        let label_len = bytes[cursor] as usize;
        cursor += 1;
        if cursor + label_len > bytes.len() - 64 {
            return Err(InviteError::TooShort(bytes.len()));
        }
        let label_str = std::str::from_utf8(&bytes[cursor..cursor + label_len])
            .map_err(|e| InviteError::InvalidUtf8(e.to_string()))?
            .to_string();
        cursor += label_len;

        // expiry (8 bytes u64 BE)
        if cursor + 8 > bytes.len() - 64 {
            return Err(InviteError::TooShort(bytes.len()));
        }
        let expiry = u64::from_be_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| InviteError::TooShort(bytes.len()))?,
        );
        cursor += 8;

        // Signature (64 bytes)
        let sig_bytes: [u8; 64] = bytes[cursor..cursor + 64]
            .try_into()
            .map_err(|_| InviteError::TooShort(bytes.len()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        // Verify signature over payload (everything before signature)
        let payload = &bytes[..cursor];
        let verifying_key =
            VerifyingKey::from_bytes(&node_id_bytes).map_err(|_| InviteError::InvalidSignature)?;
        verifying_key
            .verify(payload, &signature)
            .map_err(|_| InviteError::InvalidSignature)?;

        // Check expiry (0 = no expiry)
        if expiry > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > expiry {
                return Err(InviteError::Expired(expiry));
            }
        }

        // Derive NodeId from Ed25519 public key bytes (same encoding as identity.rs)
        let node_id = NodeId::from_bytes(node_id_bytes);

        let label = if label_str.is_empty() {
            None
        } else {
            Some(label_str)
        };

        Ok(InviteToken {
            node_id,
            addr,
            label,
            expiry,
        })
    }

    /// Build the signable payload.
    fn build_payload(node_id: &NodeId, addr: &str, label: &str, expiry: u64) -> Vec<u8> {
        let mut payload = Vec::with_capacity(32 + 1 + addr.len() + 1 + label.len() + 8);
        payload.extend_from_slice(node_id.as_bytes());
        payload.push(addr.len() as u8);
        payload.extend_from_slice(addr.as_bytes());
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
        payload.extend_from_slice(&expiry.to_be_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_identity() -> NodeIdentity {
        NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").expect("valid mnemonic")
    }

    #[test]
    fn generate_and_parse_roundtrip() {
        let identity = test_identity();
        let token =
            InviteToken::generate(&identity, "10.0.0.1:9735", Some("Alice"), 0).expect("generate");
        let parsed = InviteToken::parse(&token).expect("parse");
        assert_eq!(parsed.node_id, *identity.node_id());
        assert_eq!(parsed.addr, "10.0.0.1:9735");
        assert_eq!(parsed.label.as_deref(), Some("Alice"));
        assert_eq!(parsed.expiry, 0);
    }

    #[test]
    fn generate_and_parse_uri_roundtrip() {
        let identity = test_identity();
        let uri = InviteToken::generate_uri(&identity, "node.example.com:9735", None, 0)
            .expect("generate");
        assert!(uri.starts_with("konsensus://invite/"));
        let parsed = InviteToken::parse_uri(&uri).expect("parse");
        assert_eq!(parsed.node_id, *identity.node_id());
        assert_eq!(parsed.addr, "node.example.com:9735");
        assert!(parsed.label.is_none());
    }

    #[test]
    fn no_label() {
        let identity = test_identity();
        let token = InviteToken::generate(&identity, "127.0.0.1:3141", None, 0).expect("generate");
        let parsed = InviteToken::parse(&token).expect("parse");
        assert!(parsed.label.is_none());
    }

    #[test]
    fn with_expiry_future() {
        let identity = test_identity();
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = InviteToken::generate(&identity, "10.0.0.1:9735", Some("Test"), future_ts)
            .expect("generate");
        let parsed = InviteToken::parse(&token).expect("parse");
        assert_eq!(parsed.expiry, future_ts);
    }

    #[test]
    fn expired_token_rejected() {
        let identity = test_identity();
        let past_ts = 1000; // Unix time 1000 — definitely expired
        let token =
            InviteToken::generate(&identity, "10.0.0.1:9735", None, past_ts).expect("generate");
        let err = InviteToken::parse(&token).unwrap_err();
        assert!(matches!(err, InviteError::Expired(1000)));
    }

    #[test]
    fn tampered_signature_rejected() {
        let identity = test_identity();
        let token = InviteToken::generate(&identity, "10.0.0.1:9735", None, 0).expect("generate");
        let mut bytes = bs58::decode(&token).into_vec().unwrap();
        // Flip a byte in the signature (last 64 bytes)
        let sig_start = bytes.len() - 64;
        bytes[sig_start] ^= 0xFF;
        let tampered = bs58::encode(&bytes).into_string();
        let err = InviteToken::parse(&tampered).unwrap_err();
        assert!(matches!(err, InviteError::InvalidSignature));
    }

    #[test]
    fn tampered_address_rejected() {
        let identity = test_identity();
        let token = InviteToken::generate(&identity, "10.0.0.1:9735", None, 0).expect("generate");
        let mut bytes = bs58::decode(&token).into_vec().unwrap();
        // Flip a byte in the address area (after 32-byte node_id + 1-byte addr_len)
        bytes[33] ^= 0x01;
        let tampered = bs58::encode(&bytes).into_string();
        let err = InviteToken::parse(&tampered).unwrap_err();
        assert!(matches!(err, InviteError::InvalidSignature));
    }

    #[test]
    fn empty_address_rejected() {
        let identity = test_identity();
        let err = InviteToken::generate(&identity, "", None, 0).unwrap_err();
        assert!(matches!(err, InviteError::EmptyAddress));
    }

    #[test]
    fn too_long_address_rejected() {
        let identity = test_identity();
        let long_addr = "x".repeat(256);
        let err = InviteToken::generate(&identity, &long_addr, None, 0).unwrap_err();
        assert!(matches!(err, InviteError::AddressTooLong(256)));
    }

    #[test]
    fn too_long_label_rejected() {
        let identity = test_identity();
        let long_label = "x".repeat(256);
        let err =
            InviteToken::generate(&identity, "10.0.0.1:9735", Some(&long_label), 0).unwrap_err();
        assert!(matches!(err, InviteError::LabelTooLong(256)));
    }

    #[test]
    fn invalid_base58_rejected() {
        let err = InviteToken::parse("not-valid-base58!!!").unwrap_err();
        assert!(matches!(err, InviteError::Base58(_)));
    }

    #[test]
    fn too_short_token_rejected() {
        let err = InviteToken::parse("1234").unwrap_err();
        assert!(matches!(err, InviteError::TooShort(_)));
    }

    #[test]
    fn invalid_uri_prefix_rejected() {
        let err = InviteToken::parse_uri("https://example.com/invite/foo").unwrap_err();
        assert!(matches!(err, InviteError::InvalidUri(_)));
    }

    #[test]
    fn unicode_label_roundtrip() {
        let identity = test_identity();
        let token = InviteToken::generate(&identity, "10.0.0.1:9735", Some("Alice \u{1f512}"), 0)
            .expect("generate");
        let parsed = InviteToken::parse(&token).expect("parse");
        assert_eq!(parsed.label.as_deref(), Some("Alice \u{1f512}"));
    }

    #[test]
    fn different_identity_produces_different_token() {
        let id1 = test_identity();
        let id2 =
            NodeIdentity::from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "")
                .expect("valid");
        let t1 = InviteToken::generate(&id1, "10.0.0.1:9735", None, 0).expect("gen");
        let t2 = InviteToken::generate(&id2, "10.0.0.1:9735", None, 0).expect("gen");
        assert_ne!(t1, t2);
    }

    #[test]
    fn cross_identity_verification_fails() {
        let id1 = test_identity();
        let id2 =
            NodeIdentity::from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "")
                .expect("valid");

        // Generate with id1, tamper node_id bytes to id2's
        let token = InviteToken::generate(&id1, "10.0.0.1:9735", None, 0).expect("gen");
        let mut bytes = bs58::decode(&token).into_vec().unwrap();
        // Replace first 32 bytes with id2's node_id
        bytes[..32].copy_from_slice(id2.node_id().as_bytes());
        let tampered = bs58::encode(&bytes).into_string();
        let err = InviteToken::parse(&tampered).unwrap_err();
        assert!(matches!(err, InviteError::InvalidSignature));
    }

    #[test]
    fn bitsov_invite_sign_and_verify() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let unsigned = UnsignedBitSovInvite {
            version: SUPPORTED_INVITE_VERSION,
            inviter_pubkey: signing.verifying_key().to_bytes(),
            invitee_pubkey: [9u8; 32],
            expiry_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 120,
            channel_size_hint_sats: Some(100_000),
            addr: "node.example.com:9735".to_string(),
            max_fee_rate_sat_per_vb: Some(50),
            channel_open_intent_expiry_unix: None,
            nonce: [3u8; 16],
        };

        let invite = BitSovInvite::sign(unsigned, &signing).expect("sign");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        invite.verify(now).expect("verify");
    }

    #[test]
    fn bitsov_invite_v1_still_verifies_after_v2_upgrade() {
        let signing = SigningKey::from_bytes(&[17u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let unsigned = UnsignedBitSovInvite {
            version: LEGACY_INVITE_VERSION,
            inviter_pubkey: signing.verifying_key().to_bytes(),
            invitee_pubkey: [18u8; 32],
            expiry_unix: now + 120,
            channel_size_hint_sats: Some(100_000),
            addr: String::new(),
            max_fee_rate_sat_per_vb: None,
            channel_open_intent_expiry_unix: None,
            nonce: [8u8; 16],
        };

        let invite = BitSovInvite::sign(unsigned, &signing).expect("sign v1 invite");
        invite.verify(now).expect("v1 invite should still verify");
    }

    #[test]
    fn bitsov_invite_verify_fails_if_expired() {
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let unsigned = UnsignedBitSovInvite {
            version: 1,
            inviter_pubkey: signing.verifying_key().to_bytes(),
            invitee_pubkey: [10u8; 32],
            expiry_unix: now - 1,
            channel_size_hint_sats: None,
            addr: "node.example.com:9735".to_string(),
            max_fee_rate_sat_per_vb: Some(25),
            channel_open_intent_expiry_unix: Some(now + 60),
            nonce: [4u8; 16],
        };

        let invite = BitSovInvite::sign(unsigned, &signing).expect("sign");
        let err = invite.verify(now).expect_err("must be expired");
        assert!(matches!(err, InviteError::InviteExpired { .. }));
    }

    #[test]
    fn bitsov_invite_verify_rejects_unsupported_version() {
        let signing = SigningKey::from_bytes(&[13u8; 32]);
        let unsigned = UnsignedBitSovInvite {
            version: 99,
            inviter_pubkey: signing.verifying_key().to_bytes(),
            invitee_pubkey: [14u8; 32],
            expiry_unix: 1_700_000_000,
            channel_size_hint_sats: None,
            addr: "node.example.com:9735".to_string(),
            max_fee_rate_sat_per_vb: Some(25),
            channel_open_intent_expiry_unix: Some(1_700_000_000),
            nonce: [6u8; 16],
        };
        let err = BitSovInvite::sign(unsigned, &signing).expect_err("must reject version 99");
        assert!(matches!(err, InviteError::UnsupportedVersion(99)));
    }

    #[test]
    fn bitsov_invite_verify_fails_on_tampered_fields() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let base = BitSovInvite::sign(
            UnsignedBitSovInvite {
                version: SUPPORTED_INVITE_VERSION,
                inviter_pubkey: signing.verifying_key().to_bytes(),
                invitee_pubkey: [12u8; 32],
                expiry_unix: now + 600,
                channel_size_hint_sats: Some(50_000),
                addr: "node.example.com:9735".to_string(),
                max_fee_rate_sat_per_vb: Some(42),
                channel_open_intent_expiry_unix: Some(now + 300),
                nonce: [5u8; 16],
            },
            &signing,
        )
        .expect("sign");

        let cases: Vec<(&str, BitSovInvite)> = vec![
            (
                "version",
                BitSovInvite {
                    version: LEGACY_INVITE_VERSION,
                    ..base.clone()
                },
            ),
            (
                "inviter_pubkey",
                BitSovInvite {
                    inviter_pubkey: [99u8; 32],
                    ..base.clone()
                },
            ),
            (
                "invitee_pubkey",
                BitSovInvite {
                    invitee_pubkey: [99u8; 32],
                    ..base.clone()
                },
            ),
            (
                "expiry_unix",
                BitSovInvite {
                    expiry_unix: now + 601,
                    ..base.clone()
                },
            ),
            (
                "channel_size_hint_sats",
                BitSovInvite {
                    channel_size_hint_sats: Some(50_001),
                    ..base.clone()
                },
            ),
            (
                "addr",
                BitSovInvite {
                    addr: "other.example.com:9735".to_string(),
                    ..base.clone()
                },
            ),
            (
                "max_fee_rate_sat_per_vb",
                BitSovInvite {
                    max_fee_rate_sat_per_vb: Some(43),
                    ..base.clone()
                },
            ),
            (
                "channel_open_intent_expiry_unix",
                BitSovInvite {
                    channel_open_intent_expiry_unix: Some(now + 301),
                    ..base.clone()
                },
            ),
            (
                "nonce",
                BitSovInvite {
                    nonce: [6u8; 16],
                    ..base.clone()
                },
            ),
        ];

        for (field, invite) in cases {
            let err = invite
                .verify(now)
                .expect_err("must fail verification after post-signing tamper");
            match field {
                "inviter_pubkey" => assert!(matches!(err, InviteError::InvalidInviterPubkey)),
                _ => assert!(
                    matches!(err, InviteError::InvalidSignature),
                    "unexpected error for {field}: {err:?}"
                ),
            }
        }
    }

    #[test]
    fn bitsov_invite_canonical_bytes_changes_with_option_presence() {
        let base = BitSovInvite {
            version: 1,
            inviter_pubkey: [1u8; 32],
            invitee_pubkey: [2u8; 32],
            expiry_unix: 1_700_000_000,
            channel_size_hint_sats: None,
            addr: String::new(),
            max_fee_rate_sat_per_vb: None,
            channel_open_intent_expiry_unix: None,
            nonce: [3u8; 16],
            signature: [0u8; 64],
        };
        let mut with_hint = base.clone();
        with_hint.channel_size_hint_sats = Some(42);

        assert_ne!(
            base.canonical_bytes().expect("v1 canonical"),
            with_hint.canonical_bytes().expect("v1 canonical")
        );
    }
}
