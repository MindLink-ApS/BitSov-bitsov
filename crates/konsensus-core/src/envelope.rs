//! The Unified BitSov Message (UKM) envelope.
//!
//! One message format for ALL communication. The `kind` field (u16) determines
//! the payload schema within the encrypted `ciphertext`.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};

/// Max number of message references (threading / replies / reactions) carried
/// in a UKM envelope. A handful is all any legitimate thread needs; the cap
/// stops a hostile 16 MiB `Frame::Message`/`Frame::Gossip` from inflating
/// `references` into hundreds of thousands of `MessageId` allocations
/// (HARD-1 / SEC-PEX-WIRE bug class). konsensus-core does not depend on the
/// `bounded::` module in konsensus-message, so the cap lives here.
pub const MAX_MESSAGE_REFERENCES: usize = 64;

/// Deserialize `Vec<MessageId>` capped at [`MAX_MESSAGE_REFERENCES`]. The
/// visitor counts as it pushes and aborts at `cap + 1`, never pre-allocating
/// from the attacker-declared array length.
fn bounded_references<'de, D>(deserializer: D) -> Result<Vec<MessageId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RefVisitor;

    impl<'de> Visitor<'de> for RefVisitor {
        type Value = Vec<MessageId>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "a list of at most {MAX_MESSAGE_REFERENCES} message references"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<MessageId>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out: Vec<MessageId> = Vec::new();
            while let Some(item) = seq.next_element::<MessageId>()? {
                if out.len() >= MAX_MESSAGE_REFERENCES {
                    return Err(de::Error::custom(format!(
                        "references list exceeds maximum of {MAX_MESSAGE_REFERENCES} entries"
                    )));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(RefVisitor)
}

/// The Unified BitSov Message envelope.
///
/// Every piece of communication in the BitSov network is wrapped in this
/// envelope. The `ciphertext` is E2EE (PQXDH for 1:1, MLS for groups) and
/// the `payment_proof` is **mandatory** — no payment, no packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UkmEnvelope {
    /// Unique message identifier — blake3(ciphertext || nonce).
    pub id: MessageId,
    /// Determines payload schema within the ciphertext.
    pub kind: u16,
    /// The sender's node identity (Ed25519 public key).
    pub sender: NodeId,
    /// The intended recipient: a specific node or a room.
    pub recipient: Recipient,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// E2EE encrypted payload (PQXDH for 1:1, MLS for groups).
    pub ciphertext: Vec<u8>,
    /// Lightning payment proof — MANDATORY. Principle 2: no payment = rejected.
    pub payment_proof: PaymentProof,
    /// Ed25519 signature over the signable fields.
    pub signature: Signature,
    /// Random nonce for replay protection.
    pub nonce: Nonce,
    /// References to other messages (threading, replies, reactions).
    #[serde(deserialize_with = "bounded_references")]
    pub references: Vec<MessageId>,
}

impl UkmEnvelope {
    /// Compute the bytes that are covered by the Ed25519 signature.
    ///
    /// The signature covers:
    ///   kind || sender || recipient || timestamp || ciphertext || nonce
    ///   || payment_hash || preimage || amount_msat
    ///
    /// Including the payment proof fields prevents an intermediary from
    /// swapping the payment proof on a signed envelope (defense-in-depth:
    /// the Noise session already protects against this, but the signature
    /// should be self-sufficient).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(2 + 32 + 64 + 8 + self.ciphertext.len() + 24 + 32 + 32 + 8);
        buf.extend_from_slice(&self.kind.to_be_bytes());
        buf.extend_from_slice(self.sender.as_bytes());
        match &self.recipient {
            Recipient::Node(id) => {
                buf.push(0x01); // tag
                buf.extend_from_slice(id.as_bytes());
            }
            Recipient::Room(id) => {
                buf.push(0x02); // tag
                buf.extend_from_slice(id.as_uuid().as_bytes());
            }
            Recipient::Broadcast => {
                buf.push(0x03); // tag — no payload, broadcast has no target
            }
        }
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(self.nonce.as_bytes());
        // Payment proof fields — binds the proof to this specific envelope
        buf.extend_from_slice(&self.payment_proof.payment_hash);
        buf.extend_from_slice(&self.payment_proof.preimage);
        buf.extend_from_slice(&self.payment_proof.amount_msat.to_be_bytes());
        buf
    }

    /// Validate envelope integrity (does NOT verify the Ed25519 signature
    /// against the sender's key — that requires access to the verifying key
    /// and is done at the payment gate / transport layer).
    ///
    /// Checks:
    /// 1. MessageId matches blake3(ciphertext || nonce)
    /// 2. Ciphertext is non-empty
    /// 3. Payment proof preimage matches payment hash
    pub fn validate(&self) -> Result<(), CoreError> {
        // 1. Verify message ID
        let expected_id = MessageId::compute(&self.ciphertext, &self.nonce);
        if self.id != expected_id {
            return Err(CoreError::EnvelopeValidation(
                "message id does not match blake3(ciphertext || nonce)".into(),
            ));
        }

        // 2. Ciphertext must not be empty
        if self.ciphertext.is_empty() {
            return Err(CoreError::EnvelopeValidation(
                "ciphertext must not be empty".into(),
            ));
        }

        // 3. Payment proof must be valid (Principle 2)
        self.payment_proof.verify_preimage()?;

        // 4. References list must be bounded (defense-in-depth: the wire decoder
        //    caps this too, but validate() is the gate-side enforcement before
        //    the envelope is acted upon).
        if self.references.len() > MAX_MESSAGE_REFERENCES {
            return Err(CoreError::EnvelopeValidation(format!(
                "references list exceeds maximum of {MAX_MESSAGE_REFERENCES}"
            )));
        }

        Ok(())
    }
}

/// Builder for constructing a UKM envelope.
///
/// The builder computes the MessageId automatically from ciphertext + nonce.
/// The caller must provide the signature (signing happens at a higher layer
/// that has access to the private key).
pub struct UkmEnvelopeBuilder {
    kind: u16,
    sender: NodeId,
    recipient: Recipient,
    timestamp: u64,
    ciphertext: Vec<u8>,
    payment_proof: PaymentProof,
    signature: Signature,
    nonce: Nonce,
    references: Vec<MessageId>,
}

impl UkmEnvelopeBuilder {
    /// Start building a new envelope.
    pub fn new(
        kind: u16,
        sender: NodeId,
        recipient: Recipient,
        ciphertext: Vec<u8>,
        payment_proof: PaymentProof,
    ) -> Self {
        let now_ms_u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // u128→u64: epoch millis won't exceed u64 for ~584 million years
        let now_ms = u64::try_from(now_ms_u128).unwrap_or(u64::MAX);

        Self {
            kind,
            sender,
            recipient,
            timestamp: now_ms,
            ciphertext,
            payment_proof,
            signature: Signature::from_bytes([0u8; 64]),
            nonce: Nonce::generate(),
            references: Vec::new(),
        }
    }

    /// Set the timestamp (Unix milliseconds).
    pub fn timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Set a specific nonce (otherwise a random one is generated).
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set the Ed25519 signature.
    pub fn signature(mut self, sig: Signature) -> Self {
        self.signature = sig;
        self
    }

    /// Add message references (for threading/replies).
    pub fn references(mut self, refs: Vec<MessageId>) -> Self {
        self.references = refs;
        self
    }

    /// Build the envelope, computing the MessageId from ciphertext + nonce.
    pub fn build(self) -> UkmEnvelope {
        let id = MessageId::compute(&self.ciphertext, &self.nonce);
        UkmEnvelope {
            id,
            kind: self.kind,
            sender: self.sender,
            recipient: self.recipient,
            timestamp: self.timestamp,
            ciphertext: self.ciphertext,
            payment_proof: self.payment_proof,
            signature: self.signature,
            nonce: self.nonce,
            references: self.references,
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::kind::KIND_CHAT;
    use crate::types::RoomId;

    fn make_valid_proof() -> PaymentProof {
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        PaymentProof::new(hash, preimage, 10)
    }

    #[test]
    fn builder_computes_correct_id() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let ciphertext = b"encrypted payload".to_vec();
        let proof = make_valid_proof();

        let nonce = Nonce::from_bytes([5u8; 24]);
        let envelope = UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ciphertext.clone(), proof)
            .nonce(nonce)
            .timestamp(1_700_000_000_000)
            .build();

        let expected_id = MessageId::compute(&ciphertext, &nonce);
        assert_eq!(envelope.id, expected_id);
    }

    #[test]
    fn validate_passes_for_valid_envelope() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Room(RoomId::new());
        let proof = make_valid_proof();

        let envelope = UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
            .timestamp(1_700_000_000_000)
            .build();

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn validate_rejects_too_many_references() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let refs = vec![MessageId::from_bytes([7u8; 32]); MAX_MESSAGE_REFERENCES + 1];
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(1_700_000_000_000)
                .references(refs)
                .build();
        assert!(envelope.validate().is_err(), "over-cap references must be rejected");

        // Exactly at the cap is accepted.
        envelope.references = vec![MessageId::from_bytes([7u8; 32]); MAX_MESSAGE_REFERENCES];
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn deserialize_rejects_too_many_references() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let refs = vec![MessageId::from_bytes([9u8; 32]); MAX_MESSAGE_REFERENCES + 5];
        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(1_700_000_000_000)
                .references(refs)
                .build();

        // Serialize (uncapped) then deserialize (capped): the bounded visitor
        // must abort the parse rather than inflate the references vector.
        let json = serde_json::to_string(&envelope).expect("serialize");
        let decoded = serde_json::from_str::<UkmEnvelope>(&json);
        assert!(
            decoded.is_err(),
            "over-cap references must be rejected at decode"
        );
    }

    #[test]
    fn validate_rejects_tampered_id() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(1_700_000_000_000)
                .build();

        // Tamper with the ID
        envelope.id = MessageId::from_bytes([0u8; 32]);
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_ciphertext() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        // Empty ciphertext — the builder will compute a valid ID for empty data,
        // but validate should still reject it.
        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, vec![], proof)
                .timestamp(1_700_000_000_000)
                .build();

        let err = envelope.validate().unwrap_err();
        assert!(err.to_string().contains("ciphertext must not be empty"));
    }

    #[test]
    fn validate_rejects_bad_payment_proof() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let bad_proof = PaymentProof::new([0u8; 32], [1u8; 32], 10);

        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), bad_proof)
                .timestamp(1_700_000_000_000)
                .build();

        let err = envelope.validate().unwrap_err();
        assert!(err.to_string().contains("preimage does not match"));
    }

    #[test]
    fn envelope_serialization_roundtrip() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let envelope = UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"test".to_vec(), proof)
            .timestamp(1_700_000_000_000)
            .build();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: UkmEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn validate_rejects_tampered_ciphertext() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"original".to_vec(), proof)
                .timestamp(1_700_000_000_000)
                .build();

        // Tamper with the ciphertext — ID no longer matches
        envelope.ciphertext = b"tampered".to_vec();
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn signable_bytes_differ_for_different_recipients() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let proof = make_valid_proof();

        let env1 = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Node(NodeId::from_bytes([2u8; 32])),
            b"data".to_vec(),
            proof.clone(),
        )
        .timestamp(1_700_000_000_000)
        .build();

        let env2 = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Node(NodeId::from_bytes([3u8; 32])),
            b"data".to_vec(),
            proof.clone(),
        )
        .timestamp(1_700_000_000_000)
        .build();

        assert_ne!(env1.signable_bytes(), env2.signable_bytes());
    }

    #[test]
    fn signable_bytes_differ_for_node_vs_room_recipient() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let proof = make_valid_proof();

        let env_node = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Node(NodeId::from_bytes([2u8; 32])),
            b"data".to_vec(),
            proof.clone(),
        )
        .timestamp(1_700_000_000_000)
        .build();

        let env_room = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Room(RoomId::new()),
            b"data".to_vec(),
            proof,
        )
        .timestamp(1_700_000_000_000)
        .build();

        // Different recipient tag (0x01 vs 0x02) — signable bytes must differ
        assert_ne!(env_node.signable_bytes(), env_room.signable_bytes());
    }

    #[test]
    fn signable_bytes_differ_for_different_timestamps() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let env1 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof.clone(),
        )
        .timestamp(1_000_000_000_000)
        .build();

        let env2 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof,
        )
        .timestamp(2_000_000_000_000)
        .build();

        assert_ne!(env1.signable_bytes(), env2.signable_bytes());
    }

    #[test]
    fn signable_bytes_differ_for_different_kinds() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();
        let nonce = Nonce::from_bytes([5u8; 24]);

        let env1 = UkmEnvelopeBuilder::new(
            0, sender, recipient, b"data".to_vec(), proof.clone(),
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        let env2 = UkmEnvelopeBuilder::new(
            100, sender, recipient, b"data".to_vec(), proof,
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        assert_ne!(env1.signable_bytes(), env2.signable_bytes());
    }

    #[test]
    fn envelope_large_ciphertext_roundtrip() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        // 1 MiB of ciphertext
        let big_ct = vec![0xABu8; 1024 * 1024];
        let envelope = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, big_ct.clone(), proof,
        )
        .timestamp(1_700_000_000_000)
        .build();

        assert!(envelope.validate().is_ok());
        assert_eq!(envelope.ciphertext.len(), 1024 * 1024);

        // Serialization roundtrip
        let json = serde_json::to_vec(&envelope).unwrap();
        let deserialized: UkmEnvelope = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized, envelope);
    }

    #[test]
    fn envelope_max_kind_value() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();

        let envelope = UkmEnvelopeBuilder::new(
            u16::MAX, sender, recipient, b"data".to_vec(), proof,
        )
        .timestamp(1_700_000_000_000)
        .build();

        assert_eq!(envelope.kind, u16::MAX);
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn envelope_with_references() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_valid_proof();
        let nonce = Nonce::from_bytes([10u8; 24]);
        let ref_id = MessageId::compute(b"parent", &nonce);

        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"reply".to_vec(), proof)
                .references(vec![ref_id])
                .build();

        assert_eq!(envelope.references.len(), 1);
        assert_eq!(envelope.references[0], ref_id);
    }

    #[test]
    fn signable_bytes_include_payment_proof() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let nonce = Nonce::from_bytes([5u8; 24]);

        let proof1 = make_valid_proof(); // preimage=[42;32], amount=10

        let preimage2 = [99u8; 32];
        let hash2: [u8; 32] = Sha256::digest(preimage2).into();
        let proof2 = PaymentProof::new(hash2, preimage2, 10);

        let env1 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof1,
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        let env2 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof2,
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        // Different payment proofs must produce different signable bytes
        assert_ne!(env1.signable_bytes(), env2.signable_bytes());
    }

    #[test]
    fn signable_bytes_include_payment_amount() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let nonce = Nonce::from_bytes([5u8; 24]);
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();

        let proof_10 = PaymentProof::new(hash, preimage, 10);
        let proof_99 = PaymentProof::new(hash, preimage, 99);

        let env1 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof_10,
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        let env2 = UkmEnvelopeBuilder::new(
            KIND_CHAT, sender, recipient, b"data".to_vec(), proof_99,
        )
        .timestamp(1_700_000_000_000)
        .nonce(nonce)
        .build();

        // Different amounts must produce different signable bytes
        assert_ne!(env1.signable_bytes(), env2.signable_bytes());
    }
}
