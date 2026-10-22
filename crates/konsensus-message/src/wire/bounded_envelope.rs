//! Wire-only envelope adapters. Core serde remains usable with TOML, Value and
//! readers; peer JSON uses borrowed tokens before any string decoding.
use super::{bounded, bounded_json};
use konsensus_core::{
    envelope::{MAX_CIPHERTEXT_BYTES, MAX_MESSAGE_REFERENCES},
    types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, RoomId, Signature},
    UkmEnvelope,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::fmt;

#[derive(Deserialize)]
#[serde(remote = "UkmEnvelope")]
struct WireEnvelope {
    #[serde(deserialize_with = "bounded::hex_32")]
    id: MessageId,
    kind: u16,
    #[serde(deserialize_with = "bounded::hex_32")]
    sender: NodeId,
    #[serde(deserialize_with = "recipient")]
    recipient: Recipient,
    timestamp: u64,
    #[serde(deserialize_with = "bounded::vec_u8::<_, MAX_CIPHERTEXT_BYTES>")]
    ciphertext: Vec<u8>,
    #[serde(deserialize_with = "WirePaymentProof::deserialize")]
    payment_proof: PaymentProof,
    #[serde(deserialize_with = "bounded::hex_64")]
    signature: Signature,
    #[serde(deserialize_with = "bounded::hex_24")]
    nonce: Nonce,
    #[serde(deserialize_with = "references")]
    references: Vec<MessageId>,
}

#[derive(Deserialize)]
#[serde(remote = "PaymentProof")]
struct WirePaymentProof {
    #[serde(deserialize_with = "hex_array")]
    payment_hash: [u8; 32],
    #[serde(deserialize_with = "hex_array")]
    preimage: [u8; 32],
    amount_msat: u64,
}

#[derive(Deserialize)]
#[serde(remote = "Recipient")]
enum WireRecipient {
    Node(#[serde(deserialize_with = "bounded::hex_32")] NodeId),
    Room(#[serde(deserialize_with = "bounded_json::string_value::<_, _, 45>")] RoomId),
    Broadcast,
}

fn recipient<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Recipient, D::Error> {
    #[derive(Deserialize)]
    struct Guarded(#[serde(deserialize_with = "WireRecipient::deserialize")] Recipient);
    bounded_json::enum_value::<D, Guarded>(deserializer).map(|value| value.0)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<UkmEnvelope>, D::Error> {
    WireEnvelope::deserialize(deserializer).map(Box::new)
}

fn references<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<MessageId>, D::Error> {
    struct References;
    impl<'de> Visitor<'de> for References {
        type Value = Vec<MessageId>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded message references")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            #[derive(Deserialize)]
            struct Reference(#[serde(deserialize_with = "bounded::hex_32")] MessageId);
            let mut out = Vec::new();
            while let Some(Reference(id)) = seq.next_element::<Reference>()? {
                if out.len() >= MAX_MESSAGE_REFERENCES {
                    return Err(de::Error::custom("references exceed element cap"));
                }
                out.push(id);
            }
            Ok(out)
        }
    }
    bounded_json::sequence(deserializer, References)
}

fn hex_array<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    // NodeId shares the same 32-byte hex encoding and pre-copy wire bound.
    bounded::hex_32::<D, NodeId>(deserializer).map(|id| *id.as_bytes())
}
