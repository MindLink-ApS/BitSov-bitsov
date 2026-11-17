//! Receipt identity for a paid envelope.
//!
//! Lightning keeps the payment hash and preimage. A BLVM chat proof has neither,
//! so the receipt key is the session debit `(tx hash, sequence)` and the proof
//! itself is stored as JSON. The prepaid amount is `amount_sats * 1000`. Each
//! accepted message debits its admission price, and the sum of those debits
//! cannot exceed the prepaid amount.

use sha2::{Digest, Sha256};

use konsensus_core::kind::KIND_CHAT;
use konsensus_core::{GatePaymentProof, UkmEnvelope};

use crate::error::StorageError;

pub struct SessionDebit {
    pub payment_request_id: String,
    pub tx_hash_hex: String,
    pub seq: i64,
    pub prepaid_msat: i64,
}

pub struct PaidIdentity {
    pub payment_hash: String,
    pub preimage: String,
    pub amount_msat: i64,
    pub proof_json: Option<String>,
    pub debit: Option<SessionDebit>,
}

pub fn paid_identity(envelope: &UkmEnvelope) -> Result<PaidIdentity, StorageError> {
    match &envelope.payment_proof {
        GatePaymentProof::Lightning(proof) => {
            let amount_msat = i64::try_from(proof.amount_msat).map_err(|_| {
                StorageError::Conversion(format!(
                    "amount_msat overflows i64: {}",
                    proof.amount_msat
                ))
            })?;
            Ok(PaidIdentity {
                payment_hash: hex::encode(proof.payment_hash),
                preimage: hex::encode(proof.preimage),
                amount_msat,
                proof_json: None,
                debit: None,
            })
        }
        proof => {
            if envelope.kind != KIND_CHAT {
                return Err(StorageError::Serialization(
                    "blvm admission is chat only".into(),
                ));
            }
            let (payment_request_id, tx_hash, seq, prepaid_msat) = debit_key(proof)?;
            let seq = i64::try_from(seq)
                .map_err(|_| StorageError::Conversion("blvm debit sequence".into()))?;
            let prepaid_msat = i64::try_from(prepaid_msat)
                .map_err(|_| StorageError::Conversion("blvm prepaid amount".into()))?;
            let proof_json = serde_json::to_string(proof)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let mut receipt = Sha256::new();
            receipt.update(b"bitsov-blvm-receipt-v1");
            receipt.update(tx_hash);
            receipt.update(seq.to_be_bytes());
            receipt.update(payment_request_id.as_bytes());
            Ok(PaidIdentity {
                payment_hash: hex::encode(receipt.finalize()),
                preimage: hex::encode(Sha256::digest(proof_json.as_bytes())),
                amount_msat: prepaid_msat,
                proof_json: Some(proof_json),
                debit: Some(SessionDebit {
                    payment_request_id,
                    tx_hash_hex: hex::encode(tx_hash),
                    seq,
                    prepaid_msat,
                }),
            })
        }
    }
}

pub fn proof_from_columns(
    payment_hash: &str,
    preimage: &str,
    amount_msat: i64,
    proof_json: Option<&str>,
) -> Result<GatePaymentProof, StorageError> {
    if let Some(json) = proof_json.filter(|json| !json.is_empty()) {
        return serde_json::from_str(json)
            .map_err(|e| StorageError::Serialization(format!("payment proof json: {e}")));
    }
    let ph_bytes: [u8; 32] = hex::decode(payment_hash)
        .map_err(|e| StorageError::Conversion(format!("payment_hash: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("payment_hash: wrong length".into()))?;
    let pi_bytes: [u8; 32] = hex::decode(preimage)
        .map_err(|e| StorageError::Conversion(format!("preimage: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("preimage: wrong length".into()))?;
    let amount_u64 = u64::try_from(amount_msat)
        .map_err(|_| StorageError::Conversion(format!("amount_msat negative: {amount_msat}")))?;
    Ok(konsensus_core::PaymentProof::new(ph_bytes, pi_bytes, amount_u64).into())
}

fn debit_key(proof: &GatePaymentProof) -> Result<(String, [u8; 32], u64, u64), StorageError> {
    match proof {
        GatePaymentProof::Lightning(_) => Err(StorageError::Serialization(
            "lightning proofs use the lightning receipt".into(),
        )),
        GatePaymentProof::BlvmCovenant {
            covenant_proof,
            amount_sats,
            ..
        } => {
            let tx_hash: [u8; 32] = Sha256::digest(covenant_proof).into();
            Ok((
                "covenant".into(),
                tx_hash,
                0,
                amount_sats.saturating_mul(1000),
            ))
        }
        GatePaymentProof::BlvmOnChainSession {
            payment_request_id,
            tx_hash,
            amount_sats,
            session_debit_seq,
            ..
        } => {
            let seq = session_debit_seq.ok_or_else(|| {
                StorageError::Serialization("chat requires a session debit sequence".into())
            })?;
            Ok((
                payment_request_id.clone(),
                *tx_hash,
                seq,
                amount_sats.saturating_mul(1000),
            ))
        }
    }
}
