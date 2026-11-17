//! Multi-path payment proofs for the UKM gate (paths 1–3).
//!
//! Path 1: Lightning preimage (existing `PaymentProof` fields).
//! Path 2: BLVM + CTV covenant proof.
//! Path 3: BLVM on-chain session (BIP70 + mempool attestation).

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::error::CoreError;
use crate::types::PaymentProof;

/// Maximum covenant proof payload size accepted at structural validation.
pub const MAX_COVENANT_PROOF_BYTES: usize = 64 * 1024;

/// Payment path identifier for policy and mesh mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentPath {
    Lightning,
    BlvmCovenant,
    BlvmOnChainSession,
}

impl PaymentPath {
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name {
            "lightning" => Some(Self::Lightning),
            "blvm_covenant" => Some(Self::BlvmCovenant),
            "blvm_on_chain_session" => Some(Self::BlvmOnChainSession),
            _ => None,
        }
    }
}

/// UKM gate payment proof — supports Lightning, BLVM/CTV, and BLVM/on-chain session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatePaymentProof {
    /// Path 1: Lightning preimage proof (SHA-256(preimage) == payment_hash).
    Lightning(PaymentProof),
    /// Path 2: CTV covenant instant settlement.
    BlvmCovenant {
        covenant_proof: Vec<u8>,
        output_index: u32,
        amount_sats: u64,
        timestamp: u64,
    },
    /// Path 3: On-chain session prepay (one tx covers N messages).
    BlvmOnChainSession {
        payment_request_id: String,
        tx_hash: [u8; 32],
        amount_sats: u64,
        timestamp: u64,
        /// Monotonic debit counter within the session (None = session open only).
        session_debit_seq: Option<u64>,
    },
}

impl GatePaymentProof {
    pub fn path(&self) -> PaymentPath {
        match self {
            Self::Lightning(_) => PaymentPath::Lightning,
            Self::BlvmCovenant { .. } => PaymentPath::BlvmCovenant,
            Self::BlvmOnChainSession { .. } => PaymentPath::BlvmOnChainSession,
        }
    }

    /// Amount in millisatoshis for gate price comparison.
    pub fn amount_msat(&self) -> u64 {
        match self {
            Self::Lightning(p) => p.amount_msat,
            Self::BlvmCovenant { amount_sats, .. }
            | Self::BlvmOnChainSession { amount_sats, .. } => amount_sats.saturating_mul(1000),
        }
    }

    pub fn as_lightning(&self) -> Option<&PaymentProof> {
        match self {
            Self::Lightning(p) => Some(p),
            _ => None,
        }
    }

    /// Lightning body. A BLVM proof is a typed refusal, not a Lightning payment.
    pub fn lightning(&self) -> Result<&PaymentProof, CoreError> {
        self.as_lightning().ok_or_else(|| {
            CoreError::InvalidPaymentProof("this path requires a lightning proof".into())
        })
    }

    pub fn lightning_mut(&mut self) -> Result<&mut PaymentProof, CoreError> {
        match self {
            Self::Lightning(proof) => Ok(proof),
            _ => Err(CoreError::InvalidPaymentProof(
                "this path requires a lightning proof".into(),
            )),
        }
    }

    /// Append payment-binding bytes to the envelope signable payload.
    pub fn append_signable_bytes(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Lightning(p) => {
                buf.extend_from_slice(&p.payment_hash);
                buf.extend_from_slice(&p.preimage);
                buf.extend_from_slice(&p.amount_msat.to_be_bytes());
            }
            Self::BlvmCovenant {
                covenant_proof,
                output_index,
                amount_sats,
                ..
            } => {
                use sha2::{Digest, Sha256};
                buf.push(0x02);
                buf.extend_from_slice(&Sha256::digest(covenant_proof));
                buf.extend_from_slice(&output_index.to_be_bytes());
                buf.extend_from_slice(&amount_sats.to_be_bytes());
            }
            Self::BlvmOnChainSession {
                payment_request_id,
                tx_hash,
                amount_sats,
                session_debit_seq,
                ..
            } => {
                buf.push(0x03);
                buf.extend_from_slice(tx_hash);
                buf.extend_from_slice(&amount_sats.to_be_bytes());
                buf.extend_from_slice(payment_request_id.as_bytes());
                match session_debit_seq {
                    Some(seq) => {
                        buf.push(0x01);
                        buf.extend_from_slice(&seq.to_be_bytes());
                    }
                    None => buf.push(0x00),
                }
            }
        }
    }

    /// Structural validation (cryptographic/backend checks happen at the gate).
    pub fn validate(&self) -> Result<(), CoreError> {
        match self {
            Self::Lightning(p) => p.verify_preimage(),
            Self::BlvmCovenant {
                covenant_proof,
                amount_sats,
                ..
            } => {
                if covenant_proof.is_empty() {
                    return Err(CoreError::InvalidPaymentProof(
                        "covenant proof must not be empty".into(),
                    ));
                }
                if covenant_proof.len() > MAX_COVENANT_PROOF_BYTES {
                    return Err(CoreError::InvalidPaymentProof(format!(
                        "covenant proof exceeds {MAX_COVENANT_PROOF_BYTES} bytes"
                    )));
                }
                if *amount_sats == 0 {
                    return Err(CoreError::InvalidPaymentProof(
                        "covenant amount must be non-zero".into(),
                    ));
                }
                Ok(())
            }
            Self::BlvmOnChainSession {
                payment_request_id,
                tx_hash,
                amount_sats,
                ..
            } => {
                if payment_request_id.is_empty() {
                    return Err(CoreError::InvalidPaymentProof(
                        "payment_request_id must not be empty".into(),
                    ));
                }
                if *tx_hash == [0u8; 32] {
                    return Err(CoreError::InvalidPaymentProof(
                        "tx_hash must not be zero".into(),
                    ));
                }
                if *amount_sats == 0 {
                    return Err(CoreError::InvalidPaymentProof(
                        "on-chain amount must be non-zero".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

impl From<PaymentProof> for GatePaymentProof {
    fn from(proof: PaymentProof) -> Self {
        Self::Lightning(proof)
    }
}

impl Serialize for GatePaymentProof {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Lightning(p) => p.serialize(serializer),
            Self::BlvmCovenant {
                covenant_proof,
                output_index,
                amount_sats,
                timestamp,
            } => {
                let mut s = serializer.serialize_struct("GatePaymentProof", 6)?;
                s.serialize_field("type", "blvm_covenant")?;
                s.serialize_field("covenant_proof", covenant_proof)?;
                s.serialize_field("output_index", output_index)?;
                s.serialize_field("amount_sats", amount_sats)?;
                s.serialize_field("timestamp", timestamp)?;
                s.end()
            }
            Self::BlvmOnChainSession {
                payment_request_id,
                tx_hash,
                amount_sats,
                timestamp,
                session_debit_seq,
            } => {
                let mut s = serializer.serialize_struct("GatePaymentProof", 7)?;
                s.serialize_field("type", "blvm_on_chain_session")?;
                s.serialize_field("payment_request_id", payment_request_id)?;
                s.serialize_field("tx_hash", &hex::encode(tx_hash))?;
                s.serialize_field("amount_sats", amount_sats)?;
                s.serialize_field("timestamp", timestamp)?;
                s.serialize_field("session_debit_seq", session_debit_seq)?;
                s.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for GatePaymentProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(GatePaymentProofVisitor)
    }
}

struct GatePaymentProofVisitor;

impl<'de> Visitor<'de> for GatePaymentProofVisitor {
    type Value = GatePaymentProof;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a payment proof object")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut type_tag: Option<String> = None;
        let mut fields: Vec<(String, serde_json::Value)> = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            if key == "type" {
                type_tag = Some(map.next_value()?);
            } else {
                fields.push((key, map.next_value()?));
            }
        }

        let obj: serde_json::Map<String, serde_json::Value> = fields.into_iter().collect();

        match type_tag.as_deref() {
            None => {
                if obj.contains_key("payment_hash")
                    && obj.contains_key("preimage")
                    && obj.contains_key("amount_msat")
                {
                    let full = obj;
                    let proof: PaymentProof =
                        serde_json::from_value(serde_json::Value::Object(full))
                            .map_err(de::Error::custom)?;
                    Ok(GatePaymentProof::Lightning(proof))
                } else {
                    Err(de::Error::custom(
                        "unknown payment proof: missing type tag and lightning fields",
                    ))
                }
            }
            Some("lightning") => {
                let mut full = obj;
                full.insert("type".into(), serde_json::Value::String("lightning".into()));
                // Re-parse without type — PaymentProof has no type field
                full.remove("type");
                let proof: PaymentProof = serde_json::from_value(serde_json::Value::Object(full))
                    .map_err(de::Error::custom)?;
                Ok(GatePaymentProof::Lightning(proof))
            }
            Some("blvm_covenant") => {
                let covenant_proof = obj
                    .get("covenant_proof")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect::<Vec<u8>>()
                    })
                    .ok_or_else(|| de::Error::custom("covenant_proof required"))?;
                let output_index = obj
                    .get("output_index")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| de::Error::custom("output_index required"))?
                    as u32;
                let amount_sats = obj
                    .get("amount_sats")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| de::Error::custom("amount_sats required"))?;
                let timestamp = obj.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
                Ok(GatePaymentProof::BlvmCovenant {
                    covenant_proof,
                    output_index,
                    amount_sats,
                    timestamp,
                })
            }
            Some("blvm_on_chain_session") => {
                let payment_request_id = obj
                    .get("payment_request_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| de::Error::custom("payment_request_id required"))?
                    .to_string();
                let tx_hash_hex = obj
                    .get("tx_hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| de::Error::custom("tx_hash required"))?;
                let tx_bytes = hex::decode(tx_hash_hex).map_err(de::Error::custom)?;
                let tx_hash: [u8; 32] = tx_bytes
                    .try_into()
                    .map_err(|_| de::Error::custom("tx_hash must be 32 bytes"))?;
                let amount_sats = obj
                    .get("amount_sats")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| de::Error::custom("amount_sats required"))?;
                let timestamp = obj.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
                let session_debit_seq = obj.get("session_debit_seq").and_then(|v| v.as_u64());
                Ok(GatePaymentProof::BlvmOnChainSession {
                    payment_request_id,
                    tx_hash,
                    amount_sats,
                    timestamp,
                    session_debit_seq,
                })
            }
            Some(other) => Err(de::Error::custom(format!(
                "unknown payment proof type: {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn lightning_proof() -> GatePaymentProof {
        let preimage = [0xABu8; 32];
        let hash = Sha256::digest(preimage);
        GatePaymentProof::Lightning(PaymentProof::new(hash.into(), preimage, 50_000))
    }

    #[test]
    fn lightning_json_roundtrip_legacy_shape() {
        let proof = lightning_proof();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains("type"));
        let decoded: GatePaymentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn blvm_on_chain_session_json_roundtrip() {
        let proof = GatePaymentProof::BlvmOnChainSession {
            payment_request_id: "req-1".into(),
            tx_hash: [0x11; 32],
            amount_sats: 150_000,
            timestamp: 1_700_000_000,
            session_debit_seq: Some(3),
        };
        let json = serde_json::to_string(&proof).unwrap();
        let decoded: GatePaymentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn amount_msat_converts_sats() {
        let proof = GatePaymentProof::BlvmOnChainSession {
            payment_request_id: "r".into(),
            tx_hash: [1; 32],
            amount_sats: 100,
            timestamp: 0,
            session_debit_seq: None,
        };
        assert_eq!(proof.amount_msat(), 100_000);
    }
}
