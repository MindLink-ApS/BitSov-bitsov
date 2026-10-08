use std::collections::{HashMap, HashSet};

use bitcoin::{
    absolute, ecdsa,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Amount, EcdsaSighashType, FeeRate, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::{
    keys::{anchor_script, ErasingSecret},
    FoundOutput, OutputKind, RecoveryError, RecoveryKeys,
};

/// Fully signed transaction and its exact fee. No broadcast is performed.
#[derive(Debug, Clone)]
pub struct Sweep {
    pub transaction: Transaction,
    pub fee: Amount,
}

impl RecoveryKeys {
    /// Sweep all supplied outputs to one standard payment script.
    ///
    /// Fees round up at the given sat/kwu rate using maximum low-S DER witness
    /// sizes. Shorter actual signatures cause a small overpayment (typically one
    /// or two witness bytes per input); there is no fee/signature-size iteration.
    /// Inputs remain in caller order. Anchor inputs use sequence 1; P2WPKH inputs
    /// opt into RBF.
    /// This signs scanner-provided amounts: see the chain trust contract at crate level.
    pub fn build_sweep(
        &self,
        outputs: &[FoundOutput],
        destination: ScriptBuf,
        feerate: FeeRate,
    ) -> Result<Sweep, RecoveryError> {
        if outputs.is_empty() {
            return Err(RecoveryError::NoOutputs);
        }
        if !(destination.is_p2pkh()
            || destination.is_p2sh()
            || destination.is_p2wpkh()
            || destination.is_p2wsh()
            || destination.is_p2tr())
        {
            return Err(RecoveryError::InvalidDestination);
        }
        if feerate == FeeRate::ZERO {
            return Err(RecoveryError::ZeroFeeRate);
        }
        let scripts: HashMap<_, _> = self
            .scripts()
            .iter()
            .map(|s| (&s.script_pubkey, s))
            .collect();
        let mut seen = HashSet::new();
        let mut total = 0u64;
        let mut descriptors = Vec::with_capacity(outputs.len());
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::with_capacity(outputs.len()),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: destination,
            }],
        };
        for output in outputs {
            if !seen.insert(output.outpoint) {
                return Err(RecoveryError::DuplicateOutpoint);
            }
            let descriptor = scripts
                .get(&output.txout.script_pubkey)
                .ok_or(RecoveryError::UnknownScript)?;
            if output.confirmations == 0 {
                return Err(RecoveryError::UnconfirmedOutput);
            }
            let value = output.txout.value.to_sat();
            if value == 0 {
                return Err(RecoveryError::InvalidAmount);
            }
            total = total
                .checked_add(value)
                .filter(|v| *v <= Amount::MAX_MONEY.to_sat())
                .ok_or(RecoveryError::InvalidAmount)?;
            let (sequence, second_item_len) = match descriptor.kind {
                OutputKind::StaticRemoteKey => (Sequence::ENABLE_RBF_NO_LOCKTIME, 33),
                OutputKind::AnchorToRemote => (Sequence::from_height(1), 37),
            };
            // 72 = maximum low-S DER signature (71) plus SIGHASH_ALL (1).
            let witness = Witness::from_slice(&[vec![0; 72], vec![0; second_item_len]]);
            tx.input.push(TxIn {
                previous_output: output.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness,
            });
            descriptors.push(*descriptor);
        }
        if tx.weight().to_wu() > 400_000 {
            return Err(RecoveryError::TooHeavy);
        }
        let fee = feerate
            .fee_wu(tx.weight())
            .ok_or(RecoveryError::FeeOverflow)?;
        let value = total
            .checked_sub(fee.to_sat())
            .filter(|v| *v > 0)
            .ok_or(RecoveryError::InsufficientFunds)?;
        if value < tx.output[0].script_pubkey.minimal_non_dust().to_sat() {
            return Err(RecoveryError::DustOutput);
        }
        tx.output[0].value = Amount::from_sat(value);
        let secp = Secp256k1::new();
        let mut cache = SighashCache::new(&mut tx);
        for (i, (output, descriptor)) in outputs.iter().zip(descriptors).enumerate() {
            let secret = ErasingSecret(
                SecretKey::from_slice(self.secrets[descriptor.key_index as usize].as_ref())
                    .map_err(|_| RecoveryError::Signing)?,
            );
            let public = PublicKey::from_secret_key(&secp, &secret.0);
            let (hash, second_item) = match descriptor.kind {
                OutputKind::StaticRemoteKey => (
                    cache
                        .p2wpkh_signature_hash(
                            i,
                            &output.txout.script_pubkey,
                            output.txout.value,
                            EcdsaSighashType::All,
                        )
                        .map_err(|_| RecoveryError::Signing)?,
                    public.serialize().to_vec(),
                ),
                OutputKind::AnchorToRemote => {
                    let script = anchor_script(&public);
                    let hash = cache
                        .p2wsh_signature_hash(i, &script, output.txout.value, EcdsaSighashType::All)
                        .map_err(|_| RecoveryError::Signing)?;
                    (hash, script.into_bytes())
                }
            };
            let signature =
                ecdsa::Signature::sighash_all(secp.sign_ecdsa(&Message::from(hash), &secret.0));
            *cache.witness_mut(i).ok_or(RecoveryError::Signing)? =
                Witness::from_slice(&[signature.to_vec(), second_item]);
        }
        Ok(Sweep {
            transaction: tx,
            fee,
        })
    }
}
