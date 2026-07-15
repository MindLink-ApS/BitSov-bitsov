//! Wire protocol — frame types and length-prefixed binary framing.
//!
//! All communication between nodes uses this framing layer. Frames are serialized
//! as JSON (leveraging existing serde impls on UkmEnvelope) and then encrypted
//! by the Noise_XX transport layer before transmission.
//!
//! # Wire format
//!
//! After the Noise handshake, all data flows as length-prefixed frames:
//!
//! ```text
//! [4 bytes: frame length (u32 big-endian)] [frame data (JSON)]
//! ```
//!
//! The frame data is encrypted by Noise before going on the wire. Since Noise
//! messages have a 65535-byte limit, large frames are chunked into multiple
//! Noise messages with their own length prefix:
//!
//! ```text
//! [2 bytes: chunk length (u16 BE)] [encrypted chunk]
//! [2 bytes: chunk length (u16 BE)] [encrypted chunk]
//! ...
//! ```

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::types::{MessageId, NodeId};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors from wire protocol operations.
#[derive(Debug, Error)]
pub enum WireError {
    /// JSON serialization/deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Frame exceeds maximum allowed size.
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    /// Incomplete data received (connection likely dropped).
    #[error("incomplete frame: expected {expected} bytes, got {got}")]
    IncompleteFrame { expected: usize, got: usize },

    /// Invalid frame data.
    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    /// I/O error during read/write.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Maximum frame size: 16 MiB. Generous for file transfers but prevents OOM.
///
/// This is the **single shared** outer-frame byte cap. Both the wire
/// length-prefix decoder ([`decode_frame`]) and the Noise transport reader
/// ([`crate::transport`]) derive their limits from this constant — there is one
/// numeric definition for the whole crate, so the two layers can never drift.
///
/// HARD-1: bounding the outer frame is necessary but **not sufficient**. A
/// single ≤16 MiB JSON frame can still amplify into a far larger in-memory
/// structure (small tokens like `0,` or `null` expand into multi-byte `Vec`
/// elements / `serde_json::Value` nodes, and deeply nested JSON can exhaust the
/// stack). The per-field caps below close that pre-auth amplification window by
/// rejecting hostile collections/values *at deserialize time*, before the
/// oversized allocation happens.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Backwards-compatible alias for [`MAX_FRAME_BYTES`].
///
/// Retained so existing call sites (transport reader, tests) keep compiling.
/// There is exactly one numeric definition ([`MAX_FRAME_BYTES`]); this is a
/// pure alias, not a second source of truth.
pub const MAX_FRAME_SIZE: usize = MAX_FRAME_BYTES;

// ── HARD-1 per-field deserialize caps ────────────────────────────────────────
//
// Each cap is enforced *inside* a custom `Visitor` (see the `bounded` module)
// that counts elements/bytes/nodes as they stream out of the JSON parser and
// errors out the moment a cap is exceeded — it never pre-allocates from an
// attacker-declared length. Caps are chosen to sit comfortably above every
// legitimate frame this protocol emits while staying small enough that the
// worst-case allocation is bounded to a few MiB rather than the full 16 MiB
// frame's worth of expanded structs.

/// Max elements in a small fixed-size key/signature byte vector
/// (`x25519_sig`, `x25519_public`).
///
/// Real values are 64 bytes (Ed25519 sig) and 32 bytes (X25519 pubkey). 256 is
/// ~4× the largest legitimate value — generous headroom, yet it rejects a
/// multi-megabyte hostile array after only 257 parsed bytes.
pub const MAX_KEY_BYTES: usize = 256;

/// Max elements in the ratchet-init / opaque payload byte vector
/// (`RatchetInit.payload`).
///
/// Double Ratchet payloads are small, but file-chunk-bearing ratchet messages
/// can be larger; existing tests exercise 64 KiB. 1 MiB leaves ample room for
/// any single ratchet payload while still being 16× smaller than the frame cap.
pub const MAX_RATCHET_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Max number of advertised capabilities in a `Hello` / `HelloAck` frame.
///
/// The fixed capability set is tiny; even with application-defined `Custom`
/// entries a healthy node advertises a handful. 256 tolerates aggressive
/// experimentation (an existing test sends 100) while bounding the `Vec` and,
/// critically, the sum of `Custom(String)` allocations behind it.
pub const MAX_CAPABILITIES: usize = 256;

/// Max number of entries in a `PriceTable.prices` map.
///
/// The v2 kind taxonomy has on the order of a dozen pricing categories. 512 is
/// far above any legitimate table yet stops a hostile peer from forcing a giant
/// `HashMap<String, u64>` (each entry is a heap `String` key) out of a frame
/// stuffed with `"x":0,` pairs.
pub const MAX_PRICE_ENTRIES: usize = 512;

/// Max number of entries in a `PeerExchangeResponse.peers` list.
///
/// The protocol documents a responder-side cap of 50 shared peers. 64 matches
/// that intent with a little headroom; a 51st+ entry from a hostile peer is
/// rejected at decode rather than after building a large `Vec<PeerExchangeEntry>`.
pub const MAX_PEER_EXCHANGE_ENTRIES: usize = 64;

/// Max UTF-8 byte length of a `PeerExchangeEntry.label`.
///
/// Labels are short human-readable nicknames ("Alice's node"). 256 bytes is
/// generous for any honest label while preventing a hostile peer-exchange entry
/// from carrying a multi-megabyte string: the `MAX_PEER_EXCHANGE_ENTRIES` count
/// cap bounds the *number* of entries, but without this each entry's label was
/// an unbounded `String` (validate-before-allocate gap).
pub const MAX_PEER_LABEL_BYTES: usize = 256;

/// Max number of JSON value nodes (scalars + container slots) permitted in a
/// `serde_json::Value` field (`PrekeyOffer.bundle`, `SessionInit.init_data`).
///
/// A legitimate prekey bundle / session-init blob is a small flat object with a
/// handful of hex-string fields. 4096 nodes is orders of magnitude above that,
/// but it caps the node-count amplification where a 16 MiB frame of `[null,...]`
/// (4 bytes each on the wire) would otherwise inflate into millions of 24-byte
/// `Value` enum nodes.
pub const MAX_JSON_VALUE_NODES: usize = 4096;

/// Max nesting depth permitted in a `serde_json::Value` field.
///
/// Legitimate prekey/session payloads are shallow (objects of strings, maybe
/// one nested level). 32 is generous for any honest structure while preventing
/// a deeply nested array/object from driving recursion toward a stack overflow
/// (defence in depth alongside serde_json's own internal recursion limit).
pub const MAX_JSON_VALUE_DEPTH: usize = 32;

/// First kind value in the real-time signaling range (400–499).
///
/// Includes call invite, call answer, ICE candidates, and call hangup.
///
/// Real-time signaling must travel as paid UKM envelopes in this kind range.
/// The legacy dedicated `Frame` variants remain decode-compatible, but
/// launch-facing nodes reject them instead of creating an unpaid control lane.
pub const KIND_REALTIME_SIGNAL_START: u16 = 400;

/// Last kind value in the real-time signaling range (400–499).
pub const KIND_REALTIME_SIGNAL_END: u16 = 499;

/// Returns `true` if `kind` falls in the real-time signaling range (400–499).
#[inline]
pub fn is_realtime_signal(kind: u16) -> bool {
    (KIND_REALTIME_SIGNAL_START..=KIND_REALTIME_SIGNAL_END).contains(&kind)
}

/// HARD-1 bounded deserializers.
///
/// Every function here is wired onto a wire-frame field via
/// `#[serde(deserialize_with = ...)]`. They share one invariant: **the cap is
/// enforced while the JSON parser streams elements out, before the oversized
/// collection/value is materialised.** None of them pre-allocate from an
/// attacker-declared length, so a hostile length-prefix or an over-long array
/// is rejected after parsing only `cap + 1` elements — never after allocating
/// the full (potentially multi-megabyte) structure.
mod bounded {
    use super::*;

    /// Deserialize a `Vec<u8>` whose element count must not exceed `MAX`.
    ///
    /// The visitor counts as it pushes; the `(MAX + 1)`-th element aborts the
    /// parse. We deliberately start from an empty `Vec` (no `with_capacity`
    /// using `size_hint`, which an attacker controls) so memory grows only with
    /// elements actually consumed.
    pub fn vec_u8<'de, D, const MAX: usize>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteVecVisitor<const MAX: usize>;

        impl<'de, const MAX: usize> Visitor<'de> for ByteVecVisitor<MAX> {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a byte array of at most {MAX} elements")
            }

            // serde_json hands `Vec<u8>` to us as a sequence of integers.
            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<u8>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out: Vec<u8> = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    if out.len() >= MAX {
                        return Err(de::Error::custom(format!(
                            "byte array exceeds maximum of {MAX} elements"
                        )));
                    }
                    out.push(byte);
                }
                Ok(out)
            }

            // Tolerate `bytes`/`byte_buf` formats for forward compatibility with
            // non-JSON transports; still length-checked before returning.
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E>
            where
                E: de::Error,
            {
                if v.len() > MAX {
                    return Err(de::Error::custom(format!(
                        "byte array exceeds maximum of {MAX} elements"
                    )));
                }
                Ok(v.to_vec())
            }
        }

        deserializer.deserialize_seq(ByteVecVisitor::<MAX>)
    }

    /// Deserialize a `Vec<Capability>` capped at [`MAX_CAPABILITIES`] elements.
    pub fn capabilities<'de, D>(deserializer: D) -> Result<Vec<Capability>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapVisitor;

        impl<'de> Visitor<'de> for CapVisitor {
            type Value = Vec<Capability>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a list of at most {MAX_CAPABILITIES} capabilities")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Capability>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out: Vec<Capability> = Vec::new();
                while let Some(cap) = seq.next_element::<Capability>()? {
                    if out.len() >= MAX_CAPABILITIES {
                        return Err(de::Error::custom(format!(
                            "capability list exceeds maximum of {MAX_CAPABILITIES} entries"
                        )));
                    }
                    out.push(cap);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(CapVisitor)
    }

    /// Deserialize a `Vec<PeerExchangeEntry>` capped at
    /// [`MAX_PEER_EXCHANGE_ENTRIES`] elements.
    pub fn peer_entries<'de, D>(deserializer: D) -> Result<Vec<PeerExchangeEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PeerVisitor;

        impl<'de> Visitor<'de> for PeerVisitor {
            type Value = Vec<PeerExchangeEntry>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a list of at most {MAX_PEER_EXCHANGE_ENTRIES} peer entries"
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<PeerExchangeEntry>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out: Vec<PeerExchangeEntry> = Vec::new();
                while let Some(entry) = seq.next_element::<PeerExchangeEntry>()? {
                    if out.len() >= MAX_PEER_EXCHANGE_ENTRIES {
                        return Err(de::Error::custom(format!(
                            "peer list exceeds maximum of {MAX_PEER_EXCHANGE_ENTRIES} entries"
                        )));
                    }
                    out.push(entry);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(PeerVisitor)
    }

    /// Deserialize an `Option<String>` peer label whose UTF-8 byte length must
    /// not exceed [`MAX_PEER_LABEL_BYTES`]. An over-long label is rejected at
    /// decode, before the oversized owned `String` is materialised, so a hostile
    /// peer-exchange entry cannot inflate memory under the entry-count cap.
    pub fn peer_label<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelVisitor;

        impl<'de> Visitor<'de> for LabelVisitor {
            type Value = String;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a peer label of at most {MAX_PEER_LABEL_BYTES} bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<String, E>
            where
                E: de::Error,
            {
                if v.len() > MAX_PEER_LABEL_BYTES {
                    return Err(de::Error::custom(format!(
                        "peer label exceeds maximum of {MAX_PEER_LABEL_BYTES} bytes"
                    )));
                }
                Ok(v.to_owned())
            }
        }

        struct OptLabelVisitor;

        impl<'de> Visitor<'de> for OptLabelVisitor {
            type Value = Option<String>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "an optional peer label of at most {MAX_PEER_LABEL_BYTES} bytes"
                )
            }

            fn visit_none<E>(self) -> Result<Option<String>, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Option<String>, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Option<String>, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_str(LabelVisitor).map(Some)
            }
        }

        deserializer.deserialize_option(OptLabelVisitor)
    }

    /// Deserialize a `HashMap<String, u64>` price table capped at
    /// [`MAX_PRICE_ENTRIES`] entries.
    pub fn price_map<'de, D>(
        deserializer: D,
    ) -> Result<std::collections::HashMap<String, u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::MapAccess;

        struct PriceMapVisitor;

        impl<'de> Visitor<'de> for PriceMapVisitor {
            type Value = std::collections::HashMap<String, u64>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a price map of at most {MAX_PRICE_ENTRIES} entries")
            }

            fn visit_map<A>(
                self,
                mut map: A,
            ) -> Result<std::collections::HashMap<String, u64>, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                while let Some((key, value)) = map.next_entry::<String, u64>()? {
                    if out.len() >= MAX_PRICE_ENTRIES {
                        return Err(de::Error::custom(format!(
                            "price table exceeds maximum of {MAX_PRICE_ENTRIES} entries"
                        )));
                    }
                    out.insert(key, value);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_map(PriceMapVisitor)
    }

    /// Deserialize a `serde_json::Value` with both a node-count cap
    /// ([`MAX_JSON_VALUE_NODES`]) and a depth cap ([`MAX_JSON_VALUE_DEPTH`])
    /// enforced *during* parsing.
    ///
    /// A naive `serde_json::Value::deserialize` would happily build the whole
    /// tree first and let us validate afterwards — too late to prevent the
    /// amplification allocation. Instead we drive a depth/count-tracking visitor
    /// that aborts mid-parse the instant either bound is crossed, so the
    /// oversized tree is never fully materialised.
    pub fn bounded_json_value<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut counter = NodeCounter {
            remaining_nodes: MAX_JSON_VALUE_NODES,
        };
        bounded_value_inner(deserializer, &mut counter, MAX_JSON_VALUE_DEPTH)
    }

    /// Shared budget for the node-count cap across one whole `Value` tree.
    struct NodeCounter {
        remaining_nodes: usize,
    }

    impl NodeCounter {
        fn charge<E: de::Error>(&mut self) -> Result<(), E> {
            if self.remaining_nodes == 0 {
                return Err(de::Error::custom(format!(
                    "JSON value exceeds maximum of {MAX_JSON_VALUE_NODES} nodes"
                )));
            }
            self.remaining_nodes -= 1;
            Ok(())
        }
    }

    /// Visit one `Value` node, charging the node budget and decrementing the
    /// remaining depth on each container descent.
    fn bounded_value_inner<'de, D>(
        deserializer: D,
        counter: &mut NodeCounter,
        depth_remaining: usize,
    ) -> Result<serde_json::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor<'c> {
            counter: &'c mut NodeCounter,
            depth_remaining: usize,
        }

        impl<'de> Visitor<'de> for ValueVisitor<'_> {
            type Value = serde_json::Value;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a bounded JSON value")
            }

            fn visit_unit<E: de::Error>(self) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::Null)
            }

            fn visit_none<E: de::Error>(self) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::Null)
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::Number(v.into()))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::Number(v.into()))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Number::from_f64(v)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<serde_json::Value, E> {
                self.counter.charge::<E>()?;
                Ok(serde_json::Value::String(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<serde_json::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                self.counter.charge::<A::Error>()?;
                if self.depth_remaining == 0 {
                    return Err(de::Error::custom(format!(
                        "JSON value exceeds maximum depth of {MAX_JSON_VALUE_DEPTH}"
                    )));
                }
                let mut arr = Vec::new();
                // `DeserializeSeed` lets each child reuse the shared counter and
                // a decremented depth, keeping the bound global across the tree.
                while let Some(child) = seq.next_element_seed(ValueSeed {
                    counter: self.counter,
                    depth_remaining: self.depth_remaining - 1,
                })? {
                    arr.push(child);
                }
                Ok(serde_json::Value::Array(arr))
            }

            fn visit_map<A>(self, mut map: A) -> Result<serde_json::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                self.counter.charge::<A::Error>()?;
                if self.depth_remaining == 0 {
                    return Err(de::Error::custom(format!(
                        "JSON value exceeds maximum depth of {MAX_JSON_VALUE_DEPTH}"
                    )));
                }
                let mut obj = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let val = map.next_value_seed(ValueSeed {
                        counter: self.counter,
                        depth_remaining: self.depth_remaining - 1,
                    })?;
                    obj.insert(key, val);
                }
                Ok(serde_json::Value::Object(obj))
            }
        }

        /// Seed that threads the shared `NodeCounter` and remaining depth into
        /// each child value so the caps stay global across the whole tree.
        struct ValueSeed<'c> {
            counter: &'c mut NodeCounter,
            depth_remaining: usize,
        }

        impl<'de> de::DeserializeSeed<'de> for ValueSeed<'_> {
            type Value = serde_json::Value;

            fn deserialize<D>(self, deserializer: D) -> Result<serde_json::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(ValueVisitor {
                    counter: self.counter,
                    depth_remaining: self.depth_remaining,
                })
            }
        }

        deserializer.deserialize_any(ValueVisitor {
            counter,
            depth_remaining,
        })
    }

    /// Concrete entry point for key/signature byte vectors (cap
    /// [`MAX_KEY_BYTES`]). `#[serde(deserialize_with = ...)]` needs a
    /// non-generic function path, so this pins the const generic.
    pub fn key_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        vec_u8::<D, MAX_KEY_BYTES>(deserializer)
    }

    /// Concrete entry point for ratchet/opaque payload byte vectors (cap
    /// [`MAX_RATCHET_PAYLOAD_BYTES`]).
    pub fn ratchet_payload_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        vec_u8::<D, MAX_RATCHET_PAYLOAD_BYTES>(deserializer)
    }
}

/// Capabilities a node can advertise during the federation handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Supports PQXDH key exchange for 1:1 E2EE.
    Pqxdh,
    /// Supports X3DH key exchange for 1:1 E2EE.
    X3dh,
    /// Supports MLS for group E2EE.
    Mls,
    /// Supports file transfer.
    FileTransfer,
    /// Supports keysend (spontaneous Lightning payments without invoice round-trip).
    ///
    /// When advertised, the node will send a `LightningInfo` frame after the
    /// federation handshake containing its Lightning pubkey. Peers can then
    /// use keysend instead of the RequestInvoice/InvoiceResponse flow.
    Keysend,
    /// Advertises that this node can act as a Tier-2 RELAY — store-and-forward
    /// sealed ciphertext for offline recipients (`RELAY_PROTOCOL.md`, ADR-034).
    ///
    /// **T2R1 compatibility wedge only.** This variant enables capability
    /// NEGOTIATION; it carries no relay behavior. A default node MUST NOT
    /// advertise it (see `konsensus-node` `default_advertised_capabilities`), and
    /// it is gated behind `[relay] enabled` config (T2R8). A relay never decrypts
    /// — it holds only ciphertext; the user's keys stay on the user's device
    /// (no custody, per the charter / ADR-034). The wire format is JSON
    /// (name-tagged), so adding this variant does not shift any existing
    /// capability's encoding.
    Relay,
    /// Application-defined capability.
    Custom(String),
}

/// The sovereignty tier of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereigntyTier {
    /// Light node — uses external infrastructure.
    T1,
    /// Standard node — self-hosted Lightning.
    T2,
    /// Sovereign node — full Bitcoin validation.
    T3,
    /// Infrastructure node — provides services to others.
    T4,
}

/// Wire protocol frame — every message between nodes is one of these.
///
/// After the Noise_XX handshake completes, the federation handshake exchanges
/// `Hello`/`HelloAck` frames. All subsequent communication uses `Message`,
/// `MessageAck`, and control frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    /// Federation handshake: initiator introduces itself.
    Hello {
        /// Protocol version (2 for BitSov v2).
        version: u16,
        /// The node's Ed25519 public key (identity).
        node_id: NodeId,
        /// X25519 public key signature: Ed25519 signature over the X25519 public key
        /// used in the Noise handshake, proving ownership of both keys.
        #[serde(deserialize_with = "bounded::key_bytes")]
        x25519_sig: Vec<u8>,
        /// The X25519 public key bytes (for verification).
        #[serde(deserialize_with = "bounded::key_bytes")]
        x25519_public: Vec<u8>,
        /// Sovereignty tier.
        tier: SovereigntyTier,
        /// Supported capabilities.
        #[serde(deserialize_with = "bounded::capabilities")]
        capabilities: Vec<Capability>,
    },

    /// Federation handshake: responder acknowledges.
    HelloAck {
        /// Protocol version.
        version: u16,
        /// The node's Ed25519 public key (identity).
        node_id: NodeId,
        /// X25519 public key signature.
        #[serde(deserialize_with = "bounded::key_bytes")]
        x25519_sig: Vec<u8>,
        /// The X25519 public key bytes.
        #[serde(deserialize_with = "bounded::key_bytes")]
        x25519_public: Vec<u8>,
        /// Sovereignty tier.
        tier: SovereigntyTier,
        /// Supported capabilities.
        #[serde(deserialize_with = "bounded::capabilities")]
        capabilities: Vec<Capability>,
    },

    /// A UKM envelope delivery.
    Message(Box<UkmEnvelope>),

    /// Acknowledgment that a message was received and accepted.
    MessageAck {
        /// The ID of the acknowledged message.
        id: MessageId,
    },

    /// Message was rejected by the recipient's payment gate.
    MessageReject {
        /// The ID of the rejected message.
        id: MessageId,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// Keepalive ping (expects Pong response).
    Ping {
        /// Opaque nonce echoed back in Pong.
        nonce: u64,
    },

    /// Keepalive pong (response to Ping).
    Pong {
        /// The nonce from the corresponding Ping.
        nonce: u64,
    },

    /// Graceful disconnect notification.
    Disconnect {
        /// Why the peer is disconnecting.
        reason: String,
    },

    /// E2EE session: offer prekey bundle to peer.
    ///
    /// Sent after federation handshake to enable X3DH key agreement.
    /// The receiving peer uses this to initiate or accept a Double Ratchet session.
    PrekeyOffer {
        /// Serialized prekey bundle (JSON).
        #[serde(deserialize_with = "bounded::bounded_json_value")]
        bundle: serde_json::Value,
    },

    /// E2EE session: initiation data (X3DH output from initiator).
    ///
    /// Sent after receiving a PrekeyOffer. Contains the ephemeral key and
    /// other X3DH outputs needed for the responder to derive the shared secret.
    SessionInit {
        /// Serialized session init data (JSON).
        #[serde(deserialize_with = "bounded::bounded_json_value")]
        init_data: serde_json::Value,
    },

    /// E2EE session: acknowledgment that session is established.
    SessionAck,

    /// E2EE session: ratchet initialization message from initiator to acceptor.
    ///
    /// After X3DH session establishment, the initiator sends a ratchet-encrypted
    /// payload. The acceptor decrypts it, which triggers the DH ratchet step and
    /// initializes their sending chain. Without this, the acceptor cannot encrypt
    /// messages (the Double Ratchet is asymmetric: only the initiator can send
    /// immediately after X3DH).
    RatchetInit {
        /// Ratchet-encrypted payload (opaque bytes, hex-encoded).
        #[serde(deserialize_with = "bounded::ratchet_payload_bytes")]
        payload: Vec<u8>,
    },

    /// Request a Lightning invoice from the peer.
    ///
    /// Used by the sender before composing a message — the recipient creates
    /// an invoice on THEIR wallet and returns a BOLT11 string. The sender
    /// pays the recipient's invoice to obtain the preimage for the payment
    /// proof. This ensures real economic flow from sender to recipient
    /// (Principle 2).
    RequestInvoice {
        /// Correlation ID — the sender generates a unique ID so the response
        /// can be matched to the pending request.
        request_id: String,
        /// Amount in millisatoshis.
        amount_msat: u64,
        /// Purpose description.
        purpose: String,
    },

    /// Response to a RequestInvoice — contains the BOLT11 invoice created
    /// on the recipient's Lightning wallet.
    InvoiceResponse {
        /// Correlation ID — matches the `request_id` from the request.
        request_id: String,
        /// BOLT11 payment request string.
        bolt11: String,
        /// Payment hash (hex, 32 bytes).
        payment_hash: String,
    },

    /// Error response to a RequestInvoice — sent when the recipient's Lightning
    /// wallet fails to create the invoice. This allows the sender to fail fast
    /// instead of waiting for the 30-second timeout.
    InvoiceError {
        /// Correlation ID — matches the `request_id` from the request.
        request_id: String,
        /// Human-readable error reason.
        reason: String,
    },

    /// Lightning node information — exchanged after federation handshake when
    /// a node advertises `Capability::Keysend`.
    ///
    /// Contains the node's Lightning pubkey, enabling peers to send keysend
    /// (spontaneous) payments without the RequestInvoice/InvoiceResponse
    /// round-trip. This reduces message compose latency by ~100-200ms.
    LightningInfo {
        /// Compressed Lightning node public key (hex, 66 characters).
        /// This is the pubkey of the LND/LDK/CLN node, not the Ed25519 identity key.
        ln_pubkey: String,
        /// Dialable Lightning P2P address (`host:port`) for channel opens.
        ///
        /// Optional for backward compatibility with pre-ONB5 nodes that only
        /// exchanged the pubkey for keysend payments.
        #[serde(default)]
        ln_addr: Option<String>,
    },

    /// Price table announcement — a node's current pricing for all kind categories.
    ///
    /// Sent after federation handshake completes, and again whenever pricing
    /// changes (e.g., fee rate update causes price recalculation). The
    /// `block_height` anchors the prices to a specific point on the timechain,
    /// allowing the recipient to verify pricing freshness.
    ///
    /// Without this, senders use their own pricing engine to determine payment
    /// amounts, which may not match the recipient's required price — causing
    /// silent message rejection.
    PriceTable {
        /// Prices per kind category in millisatoshis.
        /// Key is the category name (e.g., "communication", "files_media").
        #[serde(deserialize_with = "bounded::price_map")]
        prices: std::collections::HashMap<String, u64>,
        /// Block height at which these prices were computed.
        /// Peers can verify freshness and reject stale tables.
        block_height: u64,
        /// How many blocks this price table is valid for (0 = until replaced).
        valid_blocks: u32,
        /// Plasticity trust discount for the receiving peer (0.0 to 0.5).
        ///
        /// Computed from the sender's synaptic weight for the recipient:
        /// `discount = MAX_TRUST_DISCOUNT * weight`. A weight of 1.0 (fully
        /// trusted peer) yields the maximum 50% discount. New or untrusted
        /// peers get 0.0 (no discount).
        ///
        /// This implements v2.1 plasticity pricing: reliable peers pay less.
        /// Default 0.0 for backward compatibility with nodes that don't
        /// support plasticity pricing.
        #[serde(default)]
        trust_discount: f64,
    },

    /// Request the peer's current price for a specific message kind.
    ///
    /// Used before composing to ensure the sender pays the exact amount
    /// the recipient requires. This prevents pricing mismatch rejections
    /// in a heterogeneous network where nodes have different configs.
    PriceQuery {
        /// The message kind to price (e.g., KIND_CHAT = 0).
        kind: u16,
    },

    /// Response to a PriceQuery with the required price.
    PriceResponse {
        /// The queried kind.
        kind: u16,
        /// Required price in millisatoshis.
        price_msat: u64,
        /// Block height at which this price was computed.
        block_height: u64,
    },

    /// Peer exchange request — ask a connected peer for its known peers.
    ///
    /// This enables mesh discovery: a new node connects to bootstrap peers
    /// and asks them for other nodes to connect to. The responder decides
    /// which peers to share based on its own policy (e.g., only peers that
    /// opted in to discovery, or only certain tiers).
    ///
    /// **Principle 3 compliance:** Receiving peer entries does NOT auto-whitelist
    /// them. The requesting node still must explicitly add peers to its whitelist
    /// before accepting connections from them.
    PeerExchangeRequest,

    /// Peer exchange response — list of known peer entries.
    ///
    /// Contains a curated list of peer entries the responder is willing to share.
    /// Each entry includes the node's Ed25519 public key, network address,
    /// optional label, and sovereignty tier.
    PeerExchangeResponse {
        /// Peer entries to share. Capped at 50 entries to prevent abuse.
        #[serde(deserialize_with = "bounded::peer_entries")]
        peers: Vec<PeerExchangeEntry>,
    },

    // ── Real-time Signaling (KIND range 400–499) ──────────────────────────
    /// VoIP call offer — initiates a WebRTC session via SDP offer.
    ///
    /// The initiator sends this after generating a WebRTC SDP offer.
    /// The peer responds with `CallAnswer` to complete the negotiation.
    CallOffer {
        /// Unique session identifier (random hex, 16+ bytes).
        session_id: String,
        /// SDP offer string from the local WebRTC stack.
        sdp: String,
    },

    /// VoIP call answer — accepts a `CallOffer` with an SDP answer.
    CallAnswer {
        /// Session ID matching the corresponding `CallOffer`.
        session_id: String,
        /// SDP answer string from the local WebRTC stack.
        sdp: String,
    },

    /// ICE candidate — trickle ICE candidate for WebRTC connectivity.
    ///
    /// Sent by either side during or after the offer/answer exchange.
    /// Multiple candidates are typically exchanged per session.
    IceCandidate {
        /// Session ID of the in-progress call.
        session_id: String,
        /// Serialized ICE candidate (SDP candidate line or JSON).
        candidate: String,
    },

    /// Call end — terminates an active or pending call session.
    CallEnd {
        /// Session ID of the call to terminate.
        session_id: String,
        /// Human-readable reason (e.g., "user_hangup", "declined", "timeout").
        reason: String,
    },

    /// Legacy gossip message — public data propagated across the mesh.
    ///
    /// Launch-facing nodes currently reject free gossip frames until paid
    /// broadcast semantics land. This variant remains for decode compatibility.
    /// The envelope's `recipient` field MUST be `Recipient::Broadcast`.
    /// The `sender` field is the original author, and the signature is verified
    /// by every node that receives the gossip (preventing spoofing).
    ///
    /// Each node that receives a valid gossip message re-broadcasts it to all
    /// connected peers (except the one it received it from), with deduplication
    /// by [`MessageId`] preventing infinite loops.
    ///
    /// Valid gossip kinds: `KIND_WEB_MANIFEST` (510), `KIND_PAGE_RESPONSE` (501).
    /// Other kinds are rejected.
    Gossip(Box<UkmEnvelope>),
}

/// A peer entry shared during peer exchange.
///
/// Contains enough information for the recipient to connect to and
/// authenticate the peer. The `node_id` is the peer's Ed25519 public key,
/// which the connecting node will verify during the Noise_XX handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeEntry {
    /// The peer's Ed25519 public key (hex-encoded).
    pub node_id: NodeId,
    /// Network address (IP:port) where the peer is reachable.
    pub addr: std::net::SocketAddr,
    /// Optional human-readable label.
    #[serde(default, deserialize_with = "bounded::peer_label")]
    pub label: Option<String>,
    /// The peer's sovereignty tier.
    pub tier: SovereigntyTier,
}

impl Frame {
    /// Serialize this frame to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        serde_json::to_vec(self).map_err(|e| WireError::Serialization(e.to_string()))
    }

    /// Deserialize a frame from JSON bytes.
    ///
    /// Performs post-deserialization validation: rejects non-finite float values
    /// (NaN, Infinity) in fields like `trust_discount` to prevent malicious peers
    /// from injecting poison values that propagate through pricing calculations.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WireError> {
        let frame: Self =
            serde_json::from_slice(data).map_err(|e| WireError::Serialization(e.to_string()))?;
        frame.validate()?;
        Ok(frame)
    }

    /// Validate frame invariants that serde alone cannot enforce.
    fn validate(&self) -> Result<(), WireError> {
        if let Frame::PriceTable { trust_discount, .. } = self {
            if !trust_discount.is_finite() {
                return Err(WireError::Serialization(
                    "trust_discount must be finite (not NaN or Infinity)".into(),
                ));
            }
            if *trust_discount < 0.0 || *trust_discount > 1.0 {
                return Err(WireError::Serialization(format!(
                    "trust_discount must be in [0.0, 1.0], got {trust_discount}"
                )));
            }
        }
        Ok(())
    }
}

/// Encode a frame as a length-prefixed byte buffer.
///
/// Format: `[4 bytes: length (u32 BE)] [frame JSON bytes]`
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, WireError> {
    let payload = frame.to_bytes()?;
    let len = payload.len();
    if len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut buf = Vec::with_capacity(4 + len);
    // Safety: len <= MAX_FRAME_SIZE (16 MiB) is checked above, always fits u32
    let len_u32 = u32::try_from(len).map_err(|_| WireError::FrameTooLarge {
        size: len,
        max: MAX_FRAME_SIZE,
    })?;
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Read a length-prefixed frame from a byte buffer.
///
/// Returns `(frame, bytes_consumed)` or an error.
/// Returns `None` if the buffer doesn't contain a complete frame yet.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, WireError> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let len_u32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let len = usize::try_from(len_u32).map_err(|_| WireError::FrameTooLarge {
        size: len_u32 as usize,
        max: MAX_FRAME_SIZE,
    })?;
    if len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let total = 4 + len;
    if buf.len() < total {
        return Ok(None); // Need more data
    }

    let frame = Frame::from_bytes(&buf[4..total])?;
    Ok(Some((frame, total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::types::{Nonce, PaymentProof, Recipient, Signature};

    fn test_ln_pubkey() -> String {
        format!("02{}", "ab".repeat(32))
    }

    fn make_test_envelope() -> UkmEnvelope {
        use sha2::{Digest, Sha256};
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, 10);

        konsensus_core::UkmEnvelopeBuilder::new(
            0, // KIND_CHAT
            NodeId::from_bytes([1u8; 32]),
            Recipient::Node(NodeId::from_bytes([2u8; 32])),
            b"encrypted content".to_vec(),
            proof,
        )
        .timestamp(1_700_000_000_000)
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([5u8; 24]))
        .build()
    }

    #[test]
    fn frame_message_roundtrip() {
        let envelope = make_test_envelope();
        let frame = Frame::Message(Box::new(envelope.clone()));

        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        match decoded {
            Frame::Message(e) => assert_eq!(*e, envelope),
            _ => panic!("expected Message frame"),
        }
    }

    #[test]
    fn frame_hello_roundtrip() {
        let frame = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([1u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh, Capability::Mls],
        };

        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        match decoded {
            Frame::Hello {
                version,
                tier,
                capabilities,
                ..
            } => {
                assert_eq!(version, 2);
                assert_eq!(tier, SovereigntyTier::T2);
                assert_eq!(capabilities, vec![Capability::X3dh, Capability::Mls]);
            }
            _ => panic!("expected Hello frame"),
        }
    }

    #[test]
    fn relay_capability_serde_roundtrip() {
        // The wire format is JSON (name-tagged), so Capability::Relay serializes
        // by name and round-trips. Adding the variant does not change the encoding
        // of any existing capability.
        let cap = Capability::Relay;
        let json = serde_json::to_string(&cap).unwrap();
        assert!(
            json.contains("Relay"),
            "expected name-tagged Relay, got {json}"
        );
        let back: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Capability::Relay);

        // Sibling variants are unaffected (no discriminant shift under JSON).
        assert_eq!(
            serde_json::from_str::<Capability>(
                &serde_json::to_string(&Capability::Custom("x".into())).unwrap()
            )
            .unwrap(),
            Capability::Custom("x".into())
        );
    }

    #[test]
    fn relay_capability_frame_roundtrip() {
        // A Hello advertising Relay alongside an existing capability survives the
        // full wire codec, and an old-style Hello WITHOUT Relay still decodes —
        // proving the wedge is backward-compatible.
        let with_relay = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([7u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh, Capability::Relay],
        };
        let decoded = Frame::from_bytes(&with_relay.to_bytes().unwrap()).unwrap();
        match decoded {
            Frame::Hello { capabilities, .. } => {
                assert_eq!(capabilities, vec![Capability::X3dh, Capability::Relay]);
            }
            _ => panic!("expected Hello frame"),
        }

        // Old-style frame (no Relay) is unchanged by the new variant.
        let without_relay = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([8u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier: SovereigntyTier::T2,
            capabilities: vec![Capability::X3dh],
        };
        let decoded = Frame::from_bytes(&without_relay.to_bytes().unwrap()).unwrap();
        match decoded {
            Frame::Hello { capabilities, .. } => {
                assert!(!capabilities.contains(&Capability::Relay));
                assert_eq!(capabilities, vec![Capability::X3dh]);
            }
            _ => panic!("expected Hello frame"),
        }
    }

    #[test]
    fn frame_ping_pong_roundtrip() {
        let ping = Frame::Ping { nonce: 42 };
        let bytes = ping.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Ping { nonce } => assert_eq!(nonce, 42),
            _ => panic!("expected Ping frame"),
        }

        let pong = Frame::Pong { nonce: 42 };
        let bytes = pong.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Pong { nonce } => assert_eq!(nonce, 42),
            _ => panic!("expected Pong frame"),
        }
    }

    #[test]
    fn frame_message_ack_roundtrip() {
        let id = MessageId::compute(b"test", &Nonce::from_bytes([1u8; 24]));
        let frame = Frame::MessageAck { id };

        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        match decoded {
            Frame::MessageAck { id: decoded_id } => assert_eq!(decoded_id, id),
            _ => panic!("expected MessageAck frame"),
        }
    }

    #[test]
    fn encode_decode_frame_with_length_prefix() {
        let frame = Frame::Ping { nonce: 99 };
        let encoded = encode_frame(&frame).unwrap();

        // First 4 bytes are the length
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(len + 4, encoded.len());

        let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            Frame::Ping { nonce } => assert_eq!(nonce, 99),
            _ => panic!("expected Ping"),
        }
    }

    #[test]
    fn decode_frame_incomplete_returns_none() {
        // Too short for even the length prefix
        assert!(decode_frame(&[0, 0]).unwrap().is_none());

        // Length says 100 bytes but only 10 available
        let mut buf = vec![0, 0, 0, 100];
        buf.extend_from_slice(&[0u8; 10]);
        assert!(decode_frame(&buf).unwrap().is_none());
    }

    #[test]
    fn decode_frame_too_large_rejected() {
        // Length exceeds MAX_FRAME_SIZE
        let len = (MAX_FRAME_SIZE + 1) as u32;
        let buf = len.to_be_bytes();
        let err = decode_frame(&buf).unwrap_err();
        assert!(matches!(err, WireError::FrameTooLarge { .. }));
    }

    #[test]
    fn frame_disconnect_roundtrip() {
        let frame = Frame::Disconnect {
            reason: "going offline".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Disconnect { reason } => assert_eq!(reason, "going offline"),
            _ => panic!("expected Disconnect frame"),
        }
    }

    #[test]
    fn frame_message_reject_roundtrip() {
        let id = MessageId::compute(b"data", &Nonce::from_bytes([2u8; 24]));
        let frame = Frame::MessageReject {
            id,
            reason: "insufficient payment".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::MessageReject { id: did, reason } => {
                assert_eq!(did, id);
                assert_eq!(reason, "insufficient payment");
            }
            _ => panic!("expected MessageReject frame"),
        }
    }

    #[test]
    fn frame_ratchet_init_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let frame = Frame::RatchetInit {
            payload: payload.clone(),
        };

        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        match decoded {
            Frame::RatchetInit {
                payload: decoded_payload,
            } => assert_eq!(decoded_payload, payload),
            _ => panic!("expected RatchetInit frame"),
        }
    }

    #[test]
    fn encode_frame_with_envelope() {
        let envelope = make_test_envelope();
        let frame = Frame::Message(Box::new(envelope));
        let encoded = encode_frame(&frame).unwrap();

        let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(matches!(decoded, Frame::Message(_)));
    }

    // ── Edge case tests ───────────────────────────────────────────────

    #[test]
    fn decode_malformed_json_returns_error() {
        // Valid length prefix but garbage JSON payload
        let garbage = b"this is not valid json {{{";
        let len = (garbage.len() as u32).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(garbage);

        let result = decode_frame(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WireError::Serialization(_)));
    }

    #[test]
    fn decode_empty_json_object_returns_error() {
        // Valid JSON but not a valid Frame variant
        let payload = b"{}";
        let len = (payload.len() as u32).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(payload);

        let result = decode_frame(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_zero_length_frame() {
        // Length prefix says 0 bytes — empty JSON payload
        let buf = [0u8, 0, 0, 0];
        let result = decode_frame(&buf);
        // Zero-length payload is invalid JSON
        assert!(result.is_err());
    }

    #[test]
    fn decode_frame_empty_buffer() {
        // Completely empty buffer
        assert!(decode_frame(&[]).unwrap().is_none());
    }

    #[test]
    fn decode_frame_exactly_four_bytes_zero() {
        // 4 bytes of length prefix, no payload, length says 0
        let buf = 0u32.to_be_bytes();
        // Zero-length JSON is invalid
        assert!(decode_frame(&buf).is_err());
    }

    #[test]
    fn frame_disconnect_empty_reason() {
        let frame = Frame::Disconnect {
            reason: String::new(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Disconnect { reason } => assert!(reason.is_empty()),
            _ => panic!("expected Disconnect frame"),
        }
    }

    #[test]
    fn frame_disconnect_unicode_reason() {
        let frame = Frame::Disconnect {
            reason: "节点离线 🔌 café".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Disconnect { reason } => assert_eq!(reason, "节点离线 🔌 café"),
            _ => panic!("expected Disconnect frame"),
        }
    }

    #[test]
    fn frame_hello_empty_capabilities() {
        let frame = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([1u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier: SovereigntyTier::T1,
            capabilities: vec![],
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Hello { capabilities, .. } => assert!(capabilities.is_empty()),
            _ => panic!("expected Hello frame"),
        }
    }

    #[test]
    fn frame_hello_many_capabilities() {
        let caps: Vec<Capability> = (0..100)
            .map(|i| Capability::Custom(format!("cap-{i}")))
            .collect();
        let frame = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([1u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier: SovereigntyTier::T4,
            capabilities: caps.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Hello { capabilities, .. } => assert_eq!(capabilities.len(), 100),
            _ => panic!("expected Hello frame"),
        }
    }

    #[test]
    fn frame_ping_zero_nonce() {
        let frame = Frame::Ping { nonce: 0 };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Ping { nonce } => assert_eq!(nonce, 0),
            _ => panic!("expected Ping frame"),
        }
    }

    #[test]
    fn frame_ping_max_nonce() {
        let frame = Frame::Ping { nonce: u64::MAX };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Ping { nonce } => assert_eq!(nonce, u64::MAX),
            _ => panic!("expected Ping frame"),
        }
    }

    #[test]
    fn frame_request_invoice_zero_amount() {
        let frame = Frame::RequestInvoice {
            request_id: "req-001".into(),
            amount_msat: 0,
            purpose: "free".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RequestInvoice {
                request_id,
                amount_msat,
                ..
            } => {
                assert_eq!(request_id, "req-001");
                assert_eq!(amount_msat, 0);
            }
            _ => panic!("expected RequestInvoice frame"),
        }
    }

    #[test]
    fn frame_request_invoice_max_amount() {
        let frame = Frame::RequestInvoice {
            request_id: "req-max".into(),
            amount_msat: u64::MAX,
            purpose: "big payment".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RequestInvoice {
                request_id,
                amount_msat,
                ..
            } => {
                assert_eq!(request_id, "req-max");
                assert_eq!(amount_msat, u64::MAX);
            }
            _ => panic!("expected RequestInvoice frame"),
        }
    }

    #[test]
    fn frame_ratchet_init_empty_payload() {
        let frame = Frame::RatchetInit { payload: vec![] };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RatchetInit { payload } => assert!(payload.is_empty()),
            _ => panic!("expected RatchetInit frame"),
        }
    }

    #[test]
    fn frame_invoice_response_roundtrip() {
        let frame = Frame::InvoiceResponse {
            request_id: "req-rt".into(),
            bolt11: "lnbc1...".into(),
            payment_hash: "a".repeat(64),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::InvoiceResponse {
                request_id,
                bolt11,
                payment_hash,
            } => {
                assert_eq!(request_id, "req-rt");
                assert_eq!(bolt11, "lnbc1...");
                assert_eq!(payment_hash.len(), 64);
            }
            _ => panic!("expected InvoiceResponse frame"),
        }
    }

    #[test]
    fn frame_invoice_request_response_correlation() {
        // Verify request_id correlates request and response correctly
        let request_id = "corr-test-uuid-12345";
        let request = Frame::RequestInvoice {
            request_id: request_id.into(),
            amount_msat: 25_000,
            purpose: "konsensus message".into(),
        };
        let response = Frame::InvoiceResponse {
            request_id: request_id.into(),
            bolt11: "lnbc250n1pj...".into(),
            payment_hash: "ab".repeat(32),
        };

        // Both roundtrip correctly
        let req_bytes = request.to_bytes().unwrap();
        let resp_bytes = response.to_bytes().unwrap();
        let req_decoded = Frame::from_bytes(&req_bytes).unwrap();
        let resp_decoded = Frame::from_bytes(&resp_bytes).unwrap();

        let req_id = match req_decoded {
            Frame::RequestInvoice { request_id, .. } => request_id,
            _ => panic!("wrong frame type"),
        };
        let resp_id = match resp_decoded {
            Frame::InvoiceResponse { request_id, .. } => request_id,
            _ => panic!("wrong frame type"),
        };

        // The correlation IDs must match
        assert_eq!(req_id, resp_id);
        assert_eq!(req_id, "corr-test-uuid-12345");
    }

    #[test]
    fn frame_invoice_error_roundtrip() {
        let frame = Frame::InvoiceError {
            request_id: "req-err-123".into(),
            reason: "Lightning wallet unavailable".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::InvoiceError { request_id, reason } => {
                assert_eq!(request_id, "req-err-123");
                assert_eq!(reason, "Lightning wallet unavailable");
            }
            _ => panic!("expected InvoiceError frame"),
        }
    }

    #[test]
    fn frame_invoice_error_correlates_with_request() {
        let request_id = "corr-err-uuid-456";
        let request = Frame::RequestInvoice {
            request_id: request_id.into(),
            amount_msat: 50_000,
            purpose: "konsensus message".into(),
        };
        let error = Frame::InvoiceError {
            request_id: request_id.into(),
            reason: "invoice creation failed".into(),
        };

        let req_bytes = request.to_bytes().unwrap();
        let err_bytes = error.to_bytes().unwrap();
        let req_decoded = Frame::from_bytes(&req_bytes).unwrap();
        let err_decoded = Frame::from_bytes(&err_bytes).unwrap();

        let req_id = match req_decoded {
            Frame::RequestInvoice { request_id, .. } => request_id,
            _ => panic!("wrong frame type"),
        };
        let err_id = match err_decoded {
            Frame::InvoiceError { request_id, .. } => request_id,
            _ => panic!("wrong frame type"),
        };

        assert_eq!(req_id, err_id);
        assert_eq!(req_id, "corr-err-uuid-456");
    }

    #[test]
    fn decode_frame_with_trailing_data() {
        // Valid frame followed by extra bytes — should only consume the frame
        let frame = Frame::Ping { nonce: 7 };
        let mut encoded = encode_frame(&frame).unwrap();
        encoded.extend_from_slice(b"trailing garbage");

        let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
        assert!(consumed < encoded.len());
        match decoded {
            Frame::Ping { nonce } => assert_eq!(nonce, 7),
            _ => panic!("expected Ping frame"),
        }
    }

    #[test]
    fn decode_frame_length_at_max() {
        // Length exactly at MAX_FRAME_SIZE — should not be rejected by size check
        // (but will fail because we don't provide that much data)
        let len = MAX_FRAME_SIZE as u32;
        let buf = len.to_be_bytes();
        // Only 4 bytes available, needs MAX_FRAME_SIZE more — returns None (incomplete)
        assert!(decode_frame(&buf).unwrap().is_none());
    }

    #[test]
    fn decode_frame_length_one_over_max() {
        let len = (MAX_FRAME_SIZE + 1) as u32;
        let buf = len.to_be_bytes();
        assert!(matches!(
            decode_frame(&buf).unwrap_err(),
            WireError::FrameTooLarge { .. }
        ));
    }

    #[test]
    fn frame_session_ack_roundtrip() {
        let frame = Frame::SessionAck;
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, Frame::SessionAck));
    }

    #[test]
    fn frame_prekey_offer_roundtrip() {
        let bundle = serde_json::json!({
            "identity_key": "abc123",
            "signed_prekey": "def456",
            "one_time_prekeys": ["ghi789"]
        });
        let frame = Frame::PrekeyOffer {
            bundle: bundle.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PrekeyOffer { bundle: b } => assert_eq!(b, bundle),
            _ => panic!("expected PrekeyOffer frame"),
        }
    }

    #[test]
    fn frame_session_init_roundtrip() {
        let init = serde_json::json!({
            "ephemeral_key": "aaa",
            "ciphertext": "bbb"
        });
        let frame = Frame::SessionInit {
            init_data: init.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::SessionInit { init_data } => assert_eq!(init_data, init),
            _ => panic!("expected SessionInit frame"),
        }
    }

    // ── Price discovery frame tests ──────────────────────────────────

    #[test]
    fn frame_price_table_roundtrip() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("communication".to_string(), 10);
        prices.insert("files_media".to_string(), 100);
        prices.insert("collaboration".to_string(), 25);

        let frame = Frame::PriceTable {
            prices: prices.clone(),
            block_height: 886_000,
            valid_blocks: 144,
            trust_discount: 0.0,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceTable {
                prices: p,
                block_height,
                valid_blocks,
                trust_discount: _,
            } => {
                assert_eq!(p, prices);
                assert_eq!(block_height, 886_000);
                assert_eq!(valid_blocks, 144);
            }
            _ => panic!("expected PriceTable frame"),
        }
    }

    #[test]
    fn frame_price_table_empty_prices() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: 0.0,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceTable { prices, .. } => assert!(prices.is_empty()),
            _ => panic!("expected PriceTable frame"),
        }
    }

    #[test]
    fn frame_price_query_roundtrip() {
        let frame = Frame::PriceQuery { kind: 0 };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceQuery { kind } => assert_eq!(kind, 0),
            _ => panic!("expected PriceQuery frame"),
        }
    }

    #[test]
    fn frame_price_query_max_kind() {
        let frame = Frame::PriceQuery { kind: u16::MAX };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceQuery { kind } => assert_eq!(kind, u16::MAX),
            _ => panic!("expected PriceQuery frame"),
        }
    }

    #[test]
    fn frame_price_response_roundtrip() {
        let frame = Frame::PriceResponse {
            kind: 200,
            price_msat: 150,
            block_height: 886_000,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceResponse {
                kind,
                price_msat,
                block_height,
            } => {
                assert_eq!(kind, 200);
                assert_eq!(price_msat, 150);
                assert_eq!(block_height, 886_000);
            }
            _ => panic!("expected PriceResponse frame"),
        }
    }

    #[test]
    fn frame_price_response_zero_price() {
        // Zero-price response (e.g., control messages at 0 msat).
        let frame = Frame::PriceResponse {
            kind: 900,
            price_msat: 0,
            block_height: 886_000,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceResponse { price_msat, .. } => assert_eq!(price_msat, 0),
            _ => panic!("expected PriceResponse frame"),
        }
    }

    #[test]
    fn frame_peer_exchange_request_roundtrip() {
        let frame = Frame::PeerExchangeRequest;
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, Frame::PeerExchangeRequest));
    }

    #[test]
    fn frame_peer_exchange_response_roundtrip() {
        let node_id = NodeId::from_bytes([0xab; 32]);
        let frame = Frame::PeerExchangeResponse {
            peers: vec![
                PeerExchangeEntry {
                    node_id,
                    addr: "10.0.0.1:9735".parse().unwrap(),
                    label: Some("Alpha Node".to_string()),
                    tier: SovereigntyTier::T2,
                },
                PeerExchangeEntry {
                    node_id: NodeId::from_bytes([0xcd; 32]),
                    addr: "10.0.0.2:9735".parse().unwrap(),
                    label: None,
                    tier: SovereigntyTier::T1,
                },
            ],
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PeerExchangeResponse { peers } => {
                assert_eq!(peers.len(), 2);
                assert_eq!(peers[0].node_id, node_id);
                assert_eq!(peers[0].label.as_deref(), Some("Alpha Node"));
                assert_eq!(peers[0].tier, SovereigntyTier::T2);
                assert!(peers[1].label.is_none());
            }
            _ => panic!("expected PeerExchangeResponse frame"),
        }
    }

    #[test]
    fn frame_hello_ack_roundtrip() {
        let frame = Frame::HelloAck {
            version: 2,
            node_id: NodeId::from_bytes([0xAB; 32]),
            x25519_sig: vec![0x11; 64],
            x25519_public: vec![0x22; 32],
            tier: SovereigntyTier::T3,
            capabilities: vec![Capability::X3dh, Capability::FileTransfer],
        };

        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::HelloAck {
                version,
                node_id,
                tier,
                capabilities,
                ..
            } => {
                assert_eq!(version, 2);
                assert_eq!(node_id, NodeId::from_bytes([0xAB; 32]));
                assert_eq!(tier, SovereigntyTier::T3);
                assert_eq!(capabilities.len(), 2);
            }
            _ => panic!("expected HelloAck frame"),
        }
    }

    #[test]
    fn all_sovereignty_tiers_roundtrip() {
        for tier in [
            SovereigntyTier::T1,
            SovereigntyTier::T2,
            SovereigntyTier::T3,
            SovereigntyTier::T4,
        ] {
            let frame = Frame::Hello {
                version: 2,
                node_id: NodeId::from_bytes([1u8; 32]),
                x25519_sig: vec![],
                x25519_public: vec![],
                tier,
                capabilities: vec![],
            };
            let bytes = frame.to_bytes().unwrap();
            let decoded = Frame::from_bytes(&bytes).unwrap();
            match decoded {
                Frame::Hello { tier: t, .. } => assert_eq!(t, tier),
                _ => panic!("expected Hello frame"),
            }
        }
    }

    #[test]
    fn all_capabilities_roundtrip() {
        let caps = vec![
            Capability::Pqxdh,
            Capability::X3dh,
            Capability::Mls,
            Capability::FileTransfer,
            Capability::Custom("sovereign-browser".to_string()),
        ];
        let frame = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([1u8; 32]),
            x25519_sig: vec![],
            x25519_public: vec![],
            tier: SovereigntyTier::T2,
            capabilities: caps.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Hello { capabilities, .. } => assert_eq!(capabilities, caps),
            _ => panic!("expected Hello frame"),
        }
    }

    #[test]
    fn frame_price_table_many_categories() {
        // Price table with many categories — test HashMap serialization fidelity
        let mut prices = std::collections::HashMap::new();
        for i in 0..50 {
            prices.insert(format!("category_{i}"), i * 100);
        }
        let frame = Frame::PriceTable {
            prices: prices.clone(),
            block_height: u64::MAX,
            valid_blocks: u32::MAX,
            trust_discount: 0.0,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceTable {
                prices: p,
                block_height,
                valid_blocks,
                trust_discount: _,
            } => {
                assert_eq!(p.len(), 50);
                assert_eq!(p, prices);
                assert_eq!(block_height, u64::MAX);
                assert_eq!(valid_blocks, u32::MAX);
            }
            _ => panic!("expected PriceTable frame"),
        }
    }

    #[test]
    fn frame_peer_exchange_response_many_entries() {
        // Test with 50 entries (cap is 50)
        let peers: Vec<PeerExchangeEntry> = (0..50)
            .map(|i| {
                let mut id_bytes = [0u8; 32];
                id_bytes[0] = i;
                PeerExchangeEntry {
                    node_id: NodeId::from_bytes(id_bytes),
                    addr: format!("10.0.0.{i}:9735").parse().unwrap(),
                    label: Some(format!("Node-{i}")),
                    tier: SovereigntyTier::T2,
                }
            })
            .collect();

        let frame = Frame::PeerExchangeResponse {
            peers: peers.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PeerExchangeResponse { peers: p } => {
                assert_eq!(p.len(), 50);
                assert_eq!(p[0].label.as_deref(), Some("Node-0"));
                assert_eq!(p[49].label.as_deref(), Some("Node-49"));
            }
            _ => panic!("expected PeerExchangeResponse frame"),
        }
    }

    #[test]
    fn frame_prekey_offer_empty_bundle() {
        let frame = Frame::PrekeyOffer {
            bundle: serde_json::json!({}),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PrekeyOffer { bundle } => assert!(bundle.as_object().unwrap().is_empty()),
            _ => panic!("expected PrekeyOffer frame"),
        }
    }

    #[test]
    fn frame_session_init_complex_data() {
        let init = serde_json::json!({
            "ephemeral_key": "a".repeat(64),
            "ciphertext": "b".repeat(256),
            "one_time_prekey_index": 42,
            "nested": {"deep": [1, 2, 3]}
        });
        let frame = Frame::SessionInit {
            init_data: init.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::SessionInit { init_data } => assert_eq!(init_data, init),
            _ => panic!("expected SessionInit frame"),
        }
    }

    #[test]
    fn frame_message_reject_long_reason() {
        let id = MessageId::compute(b"data", &Nonce::from_bytes([2u8; 24]));
        let long_reason = "x".repeat(10_000);
        let frame = Frame::MessageReject {
            id,
            reason: long_reason.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::MessageReject { reason, .. } => assert_eq!(reason.len(), 10_000),
            _ => panic!("expected MessageReject frame"),
        }
    }

    #[test]
    fn frame_ratchet_init_large_payload() {
        // Ratchet init with a realistic-sized encrypted payload
        let payload = vec![0xCA; 4096];
        let frame = Frame::RatchetInit {
            payload: payload.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RatchetInit {
                payload: decoded_payload,
            } => assert_eq!(decoded_payload, payload),
            _ => panic!("expected RatchetInit frame"),
        }
    }

    #[test]
    fn encode_frame_size_boundary() {
        // Create a frame that's close to but under MAX_FRAME_SIZE
        // Use a large message reject with a very long reason
        let id = MessageId::compute(b"data", &Nonce::from_bytes([2u8; 24]));
        let frame = Frame::MessageReject {
            id,
            reason: "x".repeat(1_000_000), // 1 MB reason string
        };
        let encoded = encode_frame(&frame).unwrap();
        assert!(encoded.len() < MAX_FRAME_SIZE + 4); // length prefix + payload under limit
        let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            Frame::MessageReject { reason, .. } => assert_eq!(reason.len(), 1_000_000),
            _ => panic!("expected MessageReject frame"),
        }
    }

    #[test]
    fn multiple_frames_in_buffer() {
        // Simulate a buffer with multiple frames back-to-back
        let f1 = Frame::Ping { nonce: 1 };
        let f2 = Frame::Pong { nonce: 2 };
        let f3 = Frame::Disconnect {
            reason: "bye".into(),
        };

        let mut buf = encode_frame(&f1).unwrap();
        buf.extend(encode_frame(&f2).unwrap());
        buf.extend(encode_frame(&f3).unwrap());

        // Decode first frame
        let (frame1, consumed1) = decode_frame(&buf).unwrap().unwrap();
        assert!(matches!(frame1, Frame::Ping { nonce: 1 }));

        // Decode second frame from remainder
        let (frame2, consumed2) = decode_frame(&buf[consumed1..]).unwrap().unwrap();
        assert!(matches!(frame2, Frame::Pong { nonce: 2 }));

        // Decode third frame
        let (frame3, consumed3) = decode_frame(&buf[consumed1 + consumed2..])
            .unwrap()
            .unwrap();
        match frame3 {
            Frame::Disconnect { reason } => assert_eq!(reason, "bye"),
            _ => panic!("expected Disconnect"),
        }

        // All consumed
        assert_eq!(consumed1 + consumed2 + consumed3, buf.len());
    }

    #[test]
    fn frame_peer_exchange_response_empty() {
        let frame = Frame::PeerExchangeResponse { peers: vec![] };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PeerExchangeResponse { peers } => assert!(peers.is_empty()),
            _ => panic!("expected PeerExchangeResponse frame"),
        }
    }

    #[test]
    fn frame_lightning_info_roundtrip() {
        let test_pubkey = test_ln_pubkey();
        let frame = Frame::LightningInfo {
            ln_pubkey: test_pubkey.clone(),
            ln_addr: Some("127.0.0.1:9735".into()),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::LightningInfo { ln_pubkey, ln_addr } => {
                assert_eq!(ln_pubkey, test_pubkey);
                assert_eq!(ln_addr.as_deref(), Some("127.0.0.1:9735"));
            }
            _ => panic!("expected LightningInfo frame"),
        }
    }

    #[test]
    fn capability_keysend_serialization() {
        let cap = Capability::Keysend;
        let json = serde_json::to_string(&cap).unwrap();
        let decoded: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, Capability::Keysend);
    }

    // ── Gossip frame tests ─────────────────────────────────────────────

    #[test]
    fn frame_gossip_roundtrip() {
        use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
        use sha2::{Digest, Sha256};

        let sender = NodeId::from_bytes([0xAA; 32]);
        let ciphertext = b"gossip payload data".to_vec();
        let nonce = Nonce::generate();
        let id = MessageId::compute(&ciphertext, &nonce);

        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, 0);

        let envelope = konsensus_core::UkmEnvelope {
            id,
            kind: 510, // KIND_WEB_MANIFEST
            sender,
            recipient: Recipient::Broadcast,
            timestamp: 1_700_000_000_000,
            ciphertext,
            payment_proof: proof,
            signature: Signature::from_bytes([0u8; 64]),
            nonce,
            references: vec![],
        };

        let frame = Frame::Gossip(Box::new(envelope.clone()));
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        match decoded {
            Frame::Gossip(decoded_env) => {
                assert_eq!(decoded_env.id, envelope.id);
                assert_eq!(decoded_env.kind, 510);
                assert_eq!(decoded_env.sender, sender);
                assert_eq!(decoded_env.recipient, Recipient::Broadcast);
                assert_eq!(decoded_env.timestamp, 1_700_000_000_000);
            }
            _ => panic!("expected Gossip frame"),
        }
    }

    #[test]
    fn frame_gossip_encode_decode() {
        use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
        use sha2::{Digest, Sha256};

        let sender = NodeId::from_bytes([0xBB; 32]);
        let ciphertext = b"test gossip".to_vec();
        let nonce = Nonce::generate();
        let id = MessageId::compute(&ciphertext, &nonce);

        let preimage = [7u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, 0);

        let envelope = konsensus_core::UkmEnvelope {
            id,
            kind: 510,
            sender,
            recipient: Recipient::Broadcast,
            timestamp: 1_700_000_001_000,
            ciphertext,
            payment_proof: proof,
            signature: Signature::from_bytes([0u8; 64]),
            nonce,
            references: vec![],
        };

        let frame = Frame::Gossip(Box::new(envelope));
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded {
            Frame::Gossip(env) => {
                assert_eq!(env.kind, 510);
                assert!(matches!(env.recipient, Recipient::Broadcast));
            }
            _ => panic!("expected Gossip frame"),
        }
    }

    // ── PriceTable trust_discount validation tests ──────────────────

    #[test]
    fn price_table_rejects_nan_trust_discount() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: f64::NAN,
        };
        assert!(
            frame.validate().is_err(),
            "NaN trust_discount should be rejected"
        );
    }

    #[test]
    fn price_table_rejects_infinity_trust_discount() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: f64::INFINITY,
        };
        assert!(
            frame.validate().is_err(),
            "Infinity trust_discount should be rejected"
        );
    }

    #[test]
    fn price_table_rejects_negative_infinity_trust_discount() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: f64::NEG_INFINITY,
        };
        assert!(
            frame.validate().is_err(),
            "negative Infinity trust_discount should be rejected"
        );
    }

    #[test]
    fn price_table_rejects_out_of_range_trust_discount() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: 1.5,
        };
        assert!(
            frame.validate().is_err(),
            "trust_discount > 1.0 should be rejected"
        );

        let frame_neg = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: -0.1,
        };
        assert!(
            frame_neg.validate().is_err(),
            "negative trust_discount should be rejected"
        );
    }

    #[test]
    fn price_table_accepts_valid_trust_discount_boundaries() {
        // 0.0 (minimum)
        let frame_zero = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: 0.0,
        };
        assert!(frame_zero.validate().is_ok(), "0.0 should be valid");

        // 1.0 (maximum)
        let frame_one = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: 1.0,
        };
        assert!(frame_one.validate().is_ok(), "1.0 should be valid");

        // 0.5 (typical max discount)
        let frame_half = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: 0.5,
        };
        assert!(frame_half.validate().is_ok(), "0.5 should be valid");
    }

    #[test]
    fn price_table_nan_cannot_roundtrip() {
        // NaN frames may or may not serialize (implementation-dependent),
        // but even if they do, validate() catches them on deserialize.
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 0,
            valid_blocks: 0,
            trust_discount: f64::NAN,
        };
        match frame.to_bytes() {
            Err(_) => {} // serde_json rejected NaN — good
            Ok(bytes) => {
                // If it somehow serialized, from_bytes must still reject it
                assert!(
                    Frame::from_bytes(&bytes).is_err(),
                    "NaN should be caught by validate on deserialize"
                );
            }
        }
    }

    #[test]
    fn price_table_roundtrip_with_valid_discount() {
        let frame = Frame::PriceTable {
            prices: std::collections::HashMap::new(),
            block_height: 100_000,
            valid_blocks: 6,
            trust_discount: 0.42,
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PriceTable { trust_discount, .. } => {
                assert!((trust_discount - 0.42).abs() < f64::EPSILON);
            }
            _ => panic!("expected PriceTable"),
        }
    }

    // ── Wire protocol edge-case tests ──────────────────────────────

    /// InvoiceResponse with empty bolt11 and short payment_hash still roundtrips.
    /// Validation of these fields happens at the application layer, not wire layer.
    #[test]
    fn invoice_response_empty_bolt11_roundtrips() {
        let frame = Frame::InvoiceResponse {
            request_id: "req-1".into(),
            bolt11: String::new(),
            payment_hash: "ab".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::InvoiceResponse {
                bolt11,
                payment_hash,
                ..
            } => {
                assert!(bolt11.is_empty(), "empty bolt11 should roundtrip");
                assert_eq!(payment_hash, "ab");
            }
            _ => panic!("expected InvoiceResponse"),
        }
    }

    /// RequestInvoice with zero amount is valid at wire level (free messages).
    #[test]
    fn request_invoice_zero_amount_roundtrips() {
        let frame = Frame::RequestInvoice {
            request_id: "zero".into(),
            amount_msat: 0,
            purpose: "free".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RequestInvoice { amount_msat, .. } => assert_eq!(amount_msat, 0),
            _ => panic!("expected RequestInvoice"),
        }
    }

    /// RequestInvoice with max u64 amount roundtrips correctly.
    #[test]
    fn request_invoice_max_amount_roundtrips() {
        let frame = Frame::RequestInvoice {
            request_id: "max".into(),
            amount_msat: u64::MAX,
            purpose: "stress".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::RequestInvoice { amount_msat, .. } => assert_eq!(amount_msat, u64::MAX),
            _ => panic!("expected RequestInvoice"),
        }
    }

    /// InvoiceError with empty reason roundtrips.
    #[test]
    fn invoice_error_empty_reason_roundtrips() {
        let frame = Frame::InvoiceError {
            request_id: "err-1".into(),
            reason: String::new(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::InvoiceError { reason, .. } => assert!(reason.is_empty()),
            _ => panic!("expected InvoiceError"),
        }
    }

    /// Disconnect frame with unicode reason roundtrips correctly.
    #[test]
    fn disconnect_unicode_reason_roundtrips() {
        let frame = Frame::Disconnect {
            reason: "升级协议版本不兼容".into(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Disconnect { reason } => assert_eq!(reason, "升级协议版本不兼容"),
            _ => panic!("expected Disconnect"),
        }
    }

    /// Completely invalid JSON bytes are rejected with Serialization error.
    #[test]
    fn from_bytes_rejects_invalid_json() {
        let result = Frame::from_bytes(b"\xff\xfe not json");
        assert!(result.is_err());
        match result.unwrap_err() {
            WireError::Serialization(_) => {}
            other => panic!("expected Serialization error, got: {other:?}"),
        }
    }

    /// Empty byte slice is rejected.
    #[test]
    fn from_bytes_rejects_empty_slice() {
        let result = Frame::from_bytes(b"");
        assert!(result.is_err());
    }

    /// Valid JSON but unknown frame variant is rejected.
    #[test]
    fn from_bytes_rejects_unknown_variant() {
        let result = Frame::from_bytes(br#"{"UnknownFrame":{}}"#);
        assert!(result.is_err());
    }

    // ── HARD-1: bounded-deserialize OOM-hardening tests ──────────────────
    //
    // These prove that an over-cap length prefix / collection is rejected
    // *at decode time* — i.e. while serde streams elements out of the parser
    // — before the full oversized structure is allocated. Each hostile frame
    // is built as raw JSON (not via the typed builder, which would itself be
    // bounded) and fed straight to `Frame::from_bytes`.

    /// A `Hello.x25519_sig` byte array far over [`MAX_KEY_BYTES`] is rejected.
    ///
    /// The crafted JSON is only a few KiB on the wire (one decimal `0,` per
    /// element) yet declares `MAX_KEY_BYTES + 1` elements; the visitor aborts
    /// after consuming `MAX_KEY_BYTES + 1` bytes — it never builds the array.
    #[test]
    fn decode_rejects_oversized_key_bytes_before_allocation() {
        // Build "[0,0,...,0]" with MAX_KEY_BYTES + 100 elements (well over cap).
        let n = MAX_KEY_BYTES + 100;
        let mut sig = String::from("[");
        for i in 0..n {
            if i > 0 {
                sig.push(',');
            }
            sig.push('0');
        }
        sig.push(']');

        let json = format!(
            r#"{{"Hello":{{"version":2,"node_id":"{}","x25519_sig":{sig},"x25519_public":[0,0],"tier":"T2","capabilities":[]}}}}"#,
            "00".repeat(32)
        );

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        match err {
            WireError::Serialization(msg) => {
                assert!(
                    msg.contains("byte array exceeds maximum"),
                    "expected cap-exceeded message, got: {msg}"
                );
            }
            other => panic!("expected Serialization cap error, got: {other:?}"),
        }
    }

    /// A `Hello.x25519_sig` exactly at [`MAX_KEY_BYTES`] still decodes.
    #[test]
    fn decode_accepts_key_bytes_at_cap() {
        let n = MAX_KEY_BYTES;
        let mut sig = String::from("[");
        for i in 0..n {
            if i > 0 {
                sig.push(',');
            }
            sig.push('0');
        }
        sig.push(']');

        let json = format!(
            r#"{{"Hello":{{"version":2,"node_id":"{}","x25519_sig":{sig},"x25519_public":[0,0],"tier":"T2","capabilities":[]}}}}"#,
            "00".repeat(32)
        );

        let frame = Frame::from_bytes(json.as_bytes()).expect("at-cap key bytes must decode");
        match frame {
            Frame::Hello { x25519_sig, .. } => assert_eq!(x25519_sig.len(), MAX_KEY_BYTES),
            _ => panic!("expected Hello frame"),
        }
    }

    /// An over-cap `capabilities` list is rejected at decode.
    #[test]
    fn decode_rejects_oversized_capabilities() {
        let n = MAX_CAPABILITIES + 10;
        let mut caps = String::from("[");
        for i in 0..n {
            if i > 0 {
                caps.push(',');
            }
            if i == 1 {
                caps.push_str("\"Relay\"");
            } else {
                caps.push_str("\"X3dh\"");
            }
        }
        caps.push(']');

        let json = format!(
            r#"{{"Hello":{{"version":2,"node_id":"{}","x25519_sig":[0],"x25519_public":[0],"tier":"T2","capabilities":{caps}}}}}"#,
            "00".repeat(32)
        );

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        assert!(
            matches!(err, WireError::Serialization(_)),
            "over-cap Hello.capabilities with Capability::Relay present must still fail closed"
        );
    }

    /// An over-cap `PeerExchangeResponse.peers` list is rejected at decode.
    #[test]
    fn decode_rejects_oversized_peer_list() {
        let n = MAX_PEER_EXCHANGE_ENTRIES + 5;
        let mut peers = String::from("[");
        for i in 0..n {
            if i > 0 {
                peers.push(',');
            }
            peers.push_str(&format!(
                r#"{{"node_id":"{}","addr":"10.0.0.1:9735","label":null,"tier":"T2"}}"#,
                "00".repeat(32)
            ));
        }
        peers.push(']');

        let json = format!(r#"{{"PeerExchangeResponse":{{"peers":{peers}}}}}"#);

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, WireError::Serialization(_)));
    }

    /// An over-cap `PeerExchangeEntry.label` is rejected at decode, before the
    /// oversized owned `String` is materialised.
    #[test]
    fn decode_rejects_oversized_peer_label() {
        let label = "x".repeat(MAX_PEER_LABEL_BYTES + 1);
        let json = format!(
            r#"{{"PeerExchangeResponse":{{"peers":[{{"node_id":"{}","addr":"10.0.0.1:9735","label":"{label}","tier":"T2"}}]}}}}"#,
            "00".repeat(32)
        );

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, WireError::Serialization(_)));
    }

    /// A `PeerExchangeEntry.label` at exactly the cap -- and a null label --
    /// both decode successfully.
    #[test]
    fn decode_accepts_peer_label_at_cap_and_null() {
        let label = "x".repeat(MAX_PEER_LABEL_BYTES);
        let at_cap = format!(
            r#"{{"PeerExchangeResponse":{{"peers":[{{"node_id":"{}","addr":"10.0.0.1:9735","label":"{label}","tier":"T2"}}]}}}}"#,
            "00".repeat(32)
        );
        Frame::from_bytes(at_cap.as_bytes()).expect("label at cap must decode");

        let null_label = format!(
            r#"{{"PeerExchangeResponse":{{"peers":[{{"node_id":"{}","addr":"10.0.0.1:9735","label":null,"tier":"T2"}}]}}}}"#,
            "00".repeat(32)
        );
        Frame::from_bytes(null_label.as_bytes()).expect("null label must decode");
    }

    /// An over-cap `PriceTable.prices` map is rejected at decode.
    #[test]
    fn decode_rejects_oversized_price_table() {
        let n = MAX_PRICE_ENTRIES + 5;
        let mut entries = String::from("{");
        for i in 0..n {
            if i > 0 {
                entries.push(',');
            }
            entries.push_str(&format!(r#""cat_{i}":1"#));
        }
        entries.push('}');

        let json = format!(
            r#"{{"PriceTable":{{"prices":{entries},"block_height":1,"valid_blocks":1,"trust_discount":0.0}}}}"#
        );

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, WireError::Serialization(_)));
    }

    /// A deeply nested `serde_json::Value` is rejected by the depth cap before
    /// the recursion can threaten the stack.
    ///
    /// The frame is a few KiB on the wire but nests arrays far past
    /// [`MAX_JSON_VALUE_DEPTH`]; the visitor aborts at the depth bound.
    #[test]
    fn decode_rejects_deeply_nested_json_value() {
        let depth = MAX_JSON_VALUE_DEPTH + 50;
        let mut bundle = String::new();
        for _ in 0..depth {
            bundle.push('[');
        }
        bundle.push('1');
        for _ in 0..depth {
            bundle.push(']');
        }

        let json = format!(r#"{{"PrekeyOffer":{{"bundle":{bundle}}}}}"#);

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        match err {
            WireError::Serialization(msg) => {
                assert!(
                    msg.contains("maximum depth"),
                    "expected depth-cap message, got: {msg}"
                );
            }
            other => panic!("expected Serialization depth error, got: {other:?}"),
        }
    }

    /// A `serde_json::Value` with too many nodes (wide flat array) is rejected
    /// by the node-count cap — small wire payload, would-be huge in-memory tree.
    #[test]
    fn decode_rejects_oversized_json_value_node_count() {
        let n = MAX_JSON_VALUE_NODES + 100;
        // A flat array of `n` integers: ~2 bytes each on the wire, but `n`
        // `Value::Number` nodes (24+ bytes each) in memory if unbounded.
        let mut bundle = String::from("[");
        for i in 0..n {
            if i > 0 {
                bundle.push(',');
            }
            bundle.push('1');
        }
        bundle.push(']');

        let json = format!(r#"{{"SessionInit":{{"init_data":{bundle}}}}}"#);

        let err = Frame::from_bytes(json.as_bytes()).unwrap_err();
        match err {
            WireError::Serialization(msg) => {
                assert!(
                    msg.contains("maximum of") && msg.contains("nodes"),
                    "expected node-count-cap message, got: {msg}"
                );
            }
            other => panic!("expected Serialization node-count error, got: {other:?}"),
        }
    }

    /// A legitimate small prekey bundle still roundtrips through the bounded
    /// `serde_json::Value` deserializer.
    #[test]
    fn decode_accepts_legitimate_json_value() {
        let bundle = serde_json::json!({
            "identity_key": "aabbccdd",
            "signed_prekey": "11223344",
            "one_time_prekeys": ["aa", "bb", "cc"],
            "nested": {"a": 1, "b": [1, 2, 3]}
        });
        let frame = Frame::PrekeyOffer {
            bundle: bundle.clone(),
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::PrekeyOffer { bundle: b } => assert_eq!(b, bundle),
            _ => panic!("expected PrekeyOffer frame"),
        }
    }

    /// `MAX_FRAME_SIZE` is a pure alias of `MAX_FRAME_BYTES` — single source.
    #[test]
    fn frame_byte_caps_are_one_constant() {
        assert_eq!(MAX_FRAME_SIZE, MAX_FRAME_BYTES);
    }
}
