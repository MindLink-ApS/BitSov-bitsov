//! Identity-signed Lightning key bindings.
//!
//! A contact advertises the public key of its Lightning node so peers can pay
//! it by keysend. On its own that key is only transport data: nothing ties it
//! to the Ed25519 identity the peer was admitted under. A binding is the
//! identity key's signature over the Lightning key, with a domain tag so the
//! signature can never be mistaken for a handshake, envelope, introduction or
//! invite signature. A node keeps only bindings it has verified, and it pays a
//! contact by keysend only at a verified Lightning key.
//!
//! Peers that predate this module advertise an unsigned key. Such a key is
//! recorded as [`PeerLightningKey::Unsigned`] so the paying side can refuse
//! with a fixed reason instead of paying an unbound destination.

use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

use crate::identity::NodeIdentity;
use crate::types::NodeId;

/// Domain-separation tag prefixed to the signed bytes.
///
/// The federation handshake signs a bare 32-byte X25519 key, introductions
/// and other owner statements sign a 32-byte BLAKE3 digest under their own
/// tags; the bytes signed here are always [`SIGNED_LEN`] bytes and start with
/// this tag, so no signature made for one purpose verifies for another.
pub const DOMAIN_V1: &[u8] = b"bitsov-lightning-key-binding/v1\0";

/// Length of a compressed secp256k1 public key as lowercase hex.
pub const LN_PUBKEY_HEX_LEN: usize = 66;

/// Length of the signed bytes: tag, 32-byte node id, 66-byte hex key.
pub const SIGNED_LEN: usize = DOMAIN_V1.len() + 32 + LN_PUBKEY_HEX_LEN;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Fixed reason returned when a contact's Lightning key carries no identity
/// signature. The contact runs a version that does not sign yet.
pub const REASON_CONTACT_MUST_UPDATE: &str =
    "contact must update: Lightning key is not signed by their identity";

/// Fixed reason returned when the keysend destination is not the contact's
/// verified Lightning key.
pub const REASON_DESTINATION_MISMATCH: &str =
    "keysend destination is not the contact's verified Lightning key";

/// Fixed reason returned when the contact has no Lightning key on record.
pub const REASON_NO_BINDING: &str = "contact has no verified Lightning key";

/// Why a binding was not accepted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("Lightning pubkey must be 66 hex characters starting with 02 or 03")]
    MalformedPubkey,
    #[error("binding signature must be 64 bytes")]
    MalformedSignature,
    #[error("invalid node key")]
    InvalidNodeKey,
    #[error("binding signature does not verify")]
    InvalidSignature,
}

/// What a node knows about a peer's Lightning key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLightningKey {
    /// The identity key signed this compressed Lightning pubkey (lowercase
    /// hex). Keysend may target it.
    Verified(String),
    /// The peer advertised a key without an identity signature. Never paid.
    Unsigned,
}

impl PeerLightningKey {
    /// The verified key, if any.
    pub fn verified(&self) -> Option<&str> {
        match self {
            PeerLightningKey::Verified(key) => Some(key),
            PeerLightningKey::Unsigned => None,
        }
    }
}

/// Lowercase a compressed secp256k1 pubkey in hex, refusing anything else.
pub fn canonical_ln_pubkey(ln_pubkey: &str) -> Result<String, BindingError> {
    if ln_pubkey.len() != LN_PUBKEY_HEX_LEN
        || !(ln_pubkey.starts_with("02") || ln_pubkey.starts_with("03"))
        || !ln_pubkey.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(BindingError::MalformedPubkey);
    }
    Ok(ln_pubkey.to_ascii_lowercase())
}

/// The bytes the identity key signs: tag, node id, canonical hex key.
pub fn signable_bytes(node_id: &NodeId, ln_pubkey: &str) -> Result<Vec<u8>, BindingError> {
    let key = canonical_ln_pubkey(ln_pubkey)?;
    let mut out = Vec::with_capacity(SIGNED_LEN);
    out.extend_from_slice(DOMAIN_V1);
    out.extend_from_slice(node_id.as_bytes());
    out.extend_from_slice(key.as_bytes());
    debug_assert_eq!(out.len(), SIGNED_LEN);
    Ok(out)
}

/// Sign our own Lightning key with our identity key.
pub fn sign(identity: &NodeIdentity, ln_pubkey: &str) -> Result<Vec<u8>, BindingError> {
    let message = signable_bytes(identity.node_id(), ln_pubkey)?;
    Ok(identity.sign(&message).to_bytes().to_vec())
}

/// Verify a peer's binding. Returns the canonical key on success.
pub fn verify(node_id: &NodeId, ln_pubkey: &str, signature: &[u8]) -> Result<String, BindingError> {
    let message = signable_bytes(node_id, ln_pubkey)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| BindingError::MalformedSignature)?;
    let verifying_key = node_id
        .to_verifying_key()
        .map_err(|_| BindingError::InvalidNodeKey)?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| BindingError::InvalidSignature)?;
    canonical_ln_pubkey(ln_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NodeIdentity {
        NodeIdentity::generate().expect("identity").1
    }

    fn ln_key(prefix: &str, fill: &str) -> String {
        format!("{prefix}{}", fill.repeat(32))
    }

    #[test]
    fn signed_binding_verifies_and_canonicalizes() {
        let id = identity();
        let key = ln_key("02", "AB");
        let sig = sign(&id, &key).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert_eq!(
            verify(id.node_id(), &key, &sig).unwrap(),
            key.to_ascii_lowercase()
        );
        // Case is not part of the statement: the lowercase form verifies too.
        assert!(verify(id.node_id(), &key.to_ascii_lowercase(), &sig).is_ok());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let id = identity();
        let key = ln_key("02", "ab");
        let mut sig = sign(&id, &key).unwrap();
        sig[10] ^= 0x01;
        assert_eq!(
            verify(id.node_id(), &key, &sig),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn signature_for_another_key_is_rejected() {
        let id = identity();
        let sig = sign(&id, &ln_key("02", "ab")).unwrap();
        assert_eq!(
            verify(id.node_id(), &ln_key("02", "ac"), &sig),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn signature_by_another_identity_is_rejected() {
        let signer = identity();
        let claimed = identity();
        let key = ln_key("03", "cd");
        let sig = sign(&signer, &key).unwrap();
        assert_eq!(
            verify(claimed.node_id(), &key, &sig),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn handshake_signature_does_not_verify_as_binding() {
        // The handshake signs the bare X25519 key; it must never pass here,
        // whatever Lightning key is claimed alongside it.
        let id = identity();
        let hello_sig = id.sign(id.x25519_public().as_bytes()).to_bytes().to_vec();
        assert_eq!(
            verify(id.node_id(), &ln_key("02", "ab"), &hello_sig),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn signed_bytes_start_with_tag_and_have_fixed_length() {
        let id = identity();
        let bytes = signable_bytes(id.node_id(), &ln_key("02", "ab")).unwrap();
        assert_eq!(bytes.len(), SIGNED_LEN);
        assert!(bytes.starts_with(DOMAIN_V1));
        assert_eq!(
            &bytes[DOMAIN_V1.len()..DOMAIN_V1.len() + 32],
            id.node_id().as_bytes()
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let id = identity();
        let sig = vec![0u8; SIGNATURE_LEN];
        assert_eq!(
            verify(id.node_id(), "02abcd", &sig),
            Err(BindingError::MalformedPubkey)
        );
        assert_eq!(
            verify(id.node_id(), &ln_key("04", "ab"), &sig),
            Err(BindingError::MalformedPubkey)
        );
        assert_eq!(
            verify(id.node_id(), &ln_key("02", "zz"), &sig),
            Err(BindingError::MalformedPubkey)
        );
        assert_eq!(
            verify(id.node_id(), &ln_key("02", "ab"), &[]),
            Err(BindingError::MalformedSignature)
        );
        assert_eq!(
            verify(id.node_id(), &ln_key("02", "ab"), &sig[..63]),
            Err(BindingError::MalformedSignature)
        );
        assert_eq!(sign(&id, "not-a-key"), Err(BindingError::MalformedPubkey));
    }
}
