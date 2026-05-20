//! Federation signing — Ed25519 signatures with nonce-based replay protection.
//!
//! Ported from v1's `federation-signing.service.ts` and `nonce.service.ts`.
//! Every federation message is signed with the sender's Ed25519 key and
//! includes a unique nonce to prevent replay attacks.

use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::identity::NodeIdentity;
use crate::types::{NodeId, Nonce, Signature};

/// A signed federation message with nonce replay protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The message payload (opaque bytes — may be JSON, binary, etc.).
    pub payload: Vec<u8>,
    /// The sender's node identity.
    pub sender: NodeId,
    /// Unique nonce for replay protection.
    pub nonce: Nonce,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// Ed25519 signature over (payload || sender || nonce || timestamp).
    pub signature: Signature,
}

impl SignedMessage {
    /// Compute the bytes to be signed: payload || sender || nonce || timestamp.
    fn signable_bytes(
        payload: &[u8],
        sender: &NodeId,
        nonce: &Nonce,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.len() + 32 + 24 + 8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(sender.as_bytes());
        buf.extend_from_slice(nonce.as_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf
    }

    /// Create and sign a federation message.
    pub fn sign(identity: &NodeIdentity, payload: Vec<u8>, timestamp: u64) -> Self {
        let sender = *identity.node_id();
        let nonce = Nonce::generate();
        let signable = Self::signable_bytes(&payload, &sender, &nonce, timestamp);
        let sig = identity.sign(&signable);

        Self {
            payload,
            sender,
            nonce,
            timestamp,
            signature: Signature::from_ed25519(&sig),
        }
    }

    /// Verify the signature against the sender's public key.
    ///
    /// This checks cryptographic validity only. The caller must also
    /// check the nonce for replay protection (via storage).
    pub fn verify_signature(&self) -> Result<(), CoreError> {
        let verifying_key = self.sender.to_verifying_key()?;
        let signable =
            Self::signable_bytes(&self.payload, &self.sender, &self.nonce, self.timestamp);
        let ed_sig = self.signature.to_ed25519();

        verifying_key
            .verify(&signable, &ed_sig)
            .map_err(|e| CoreError::InvalidSignature(e.to_string()))
    }

    /// Verify signature and check that the timestamp is within an acceptable window.
    ///
    /// `max_age_ms` is the maximum acceptable age of the message in milliseconds.
    /// `now_ms` is the current Unix timestamp in milliseconds.
    pub fn verify_with_timestamp(
        &self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Result<(), CoreError> {
        self.verify_signature()?;

        // Check message isn't too old
        if self.timestamp + max_age_ms < now_ms {
            return Err(CoreError::EnvelopeValidation(format!(
                "message too old: timestamp {} is more than {}ms before now {}",
                self.timestamp, max_age_ms, now_ms
            )));
        }

        // Check message isn't from the future (with small tolerance)
        let future_tolerance_ms = 30_000; // 30 seconds
        if self.timestamp > now_ms + future_tolerance_ms {
            return Err(CoreError::EnvelopeValidation(format!(
                "message from the future: timestamp {} is after now {} + tolerance",
                self.timestamp, now_ms
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn sign_and_verify() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let payload = b"federation handshake request".to_vec();
        let now = 1_700_000_000_000u64;

        let signed = SignedMessage::sign(&identity, payload.clone(), now);

        assert_eq!(signed.payload, payload);
        assert_eq!(signed.sender, *identity.node_id());
        assert!(signed.verify_signature().is_ok());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let signed = SignedMessage::sign(&identity, b"original".to_vec(), 1_700_000_000_000);

        let mut tampered = signed;
        tampered.payload = b"tampered".to_vec();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn verify_rejects_wrong_sender() {
        let alice = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
        let bob = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();

        let mut signed = SignedMessage::sign(&alice, b"hello".to_vec(), 1_700_000_000_000);
        signed.sender = *bob.node_id(); // Claim to be Bob
        assert!(signed.verify_signature().is_err());
    }

    #[test]
    fn verify_with_timestamp_accepts_recent() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;
        let signed = SignedMessage::sign(&identity, b"hello".to_vec(), now);

        // Verify 5 seconds later, with 60 second max age
        assert!(signed.verify_with_timestamp(now + 5_000, 60_000).is_ok());
    }

    #[test]
    fn verify_with_timestamp_rejects_old() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;
        let signed = SignedMessage::sign(&identity, b"hello".to_vec(), now);

        // Verify 2 minutes later, with 60 second max age
        assert!(signed
            .verify_with_timestamp(now + 120_000, 60_000)
            .is_err());
    }

    #[test]
    fn verify_with_timestamp_rejects_future() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let far_future = 1_800_000_000_000u64;
        let now = 1_700_000_000_000u64;
        let signed = SignedMessage::sign(&identity, b"hello".to_vec(), far_future);

        assert!(signed.verify_with_timestamp(now, 60_000).is_err());
    }

    #[test]
    fn each_message_has_unique_nonce() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;

        let msg1 = SignedMessage::sign(&identity, b"one".to_vec(), now);
        let msg2 = SignedMessage::sign(&identity, b"two".to_vec(), now);

        assert_ne!(msg1.nonce, msg2.nonce);
    }

    /// Message exactly at max_age boundary should still be accepted.
    #[test]
    fn verify_at_exact_max_age_boundary() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let msg_time = 1_700_000_000_000u64;
        let max_age = 60_000u64;
        let signed = SignedMessage::sign(&identity, b"boundary".to_vec(), msg_time);

        // At exactly max_age: timestamp + max_age == now → should accept (not less than)
        assert!(signed
            .verify_with_timestamp(msg_time + max_age, max_age)
            .is_ok());
    }

    /// Message 1ms past max_age should be rejected.
    #[test]
    fn verify_one_ms_past_max_age_rejected() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let msg_time = 1_700_000_000_000u64;
        let max_age = 60_000u64;
        let signed = SignedMessage::sign(&identity, b"expired".to_vec(), msg_time);

        assert!(signed
            .verify_with_timestamp(msg_time + max_age + 1, max_age)
            .is_err());
    }

    /// Message from the future within 30s tolerance should be accepted.
    #[test]
    fn verify_future_within_tolerance_accepted() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;
        // Message timestamped 29 seconds in the future
        let signed = SignedMessage::sign(&identity, b"future".to_vec(), now + 29_000);

        assert!(signed.verify_with_timestamp(now, 60_000).is_ok());
    }

    /// Message from the future beyond 30s tolerance should be rejected.
    #[test]
    fn verify_future_beyond_tolerance_rejected() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;
        // Message timestamped 31 seconds in the future (beyond 30s tolerance)
        let signed = SignedMessage::sign(&identity, b"too-future".to_vec(), now + 31_000);

        assert!(signed.verify_with_timestamp(now, 60_000).is_err());
    }

    /// Message at exactly 30s future tolerance boundary.
    #[test]
    fn verify_at_exact_future_tolerance_boundary() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let now = 1_700_000_000_000u64;
        // Exactly at 30s boundary: timestamp == now + 30_000
        let signed = SignedMessage::sign(&identity, b"edge".to_vec(), now + 30_000);

        // now + future_tolerance_ms = now + 30_000 → timestamp not > → accepted
        assert!(signed.verify_with_timestamp(now, 60_000).is_ok());
    }

    #[test]
    fn signed_message_serialization_roundtrip() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let signed = SignedMessage::sign(&identity, b"serialize me".to_vec(), 1_700_000_000_000);

        let json = serde_json::to_string(&signed).unwrap();
        let decoded: SignedMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(signed.payload, decoded.payload);
        assert_eq!(signed.sender, decoded.sender);
        assert_eq!(signed.timestamp, decoded.timestamp);
        assert!(decoded.verify_signature().is_ok());
    }
}
