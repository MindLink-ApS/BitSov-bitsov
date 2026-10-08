use super::*;
use bitcoin::{hashes::Hash, secp256k1::Secp256k1};
use lightning::sign::KeysManager;
use proptest::prelude::*;

#[test]
fn fixed_seed_matches_every_ldk_script() {
    let keys = RecoveryKeys::from_ldk_seed(&[42; 32]).unwrap();
    let expected = KeysManager::new(&[42; 32], 0, 0, true)
        .possible_v2_counterparty_closed_balance_spks(&Secp256k1::new());
    assert_eq!(keys.scripts().len(), 2000);
    assert_eq!(
        keys.scripts()
            .iter()
            .map(|s| s.script_pubkey.clone())
            .collect::<Vec<_>>(),
        expected
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn every_script_matches_ldk_for_arbitrary_seed(seed in any::<[u8; 32]>()) {
        let keys = RecoveryKeys::from_ldk_seed(&seed).unwrap();
        let expected = KeysManager::new(&seed, 123, 456, true)
            .possible_v2_counterparty_closed_balance_spks(&Secp256k1::new());
        prop_assert_eq!(keys.scripts().iter().map(|s| s.script_pubkey.clone()).collect::<Vec<_>>(), expected);
    }
}

use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, FeeRate, OutPoint, ScriptBuf, Sequence,
    Transaction, TxOut, Txid,
};

struct MemoryScanner(Vec<FoundOutput>);
#[async_trait::async_trait]
impl Scanner for MemoryScanner {
    type Error = std::convert::Infallible;
    async fn scan(&self, scripts: &[RecoveryScript]) -> Result<Vec<FoundOutput>, Self::Error> {
        Ok(self
            .0
            .iter()
            .filter(|o| {
                scripts
                    .iter()
                    .any(|s| s.script_pubkey == o.txout.script_pubkey)
            })
            .cloned()
            .collect())
    }
}

fn found(keys: &RecoveryKeys, n: usize, sats: u64) -> FoundOutput {
    FoundOutput {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: n as u32,
        },
        txout: TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: keys.scripts()[n].script_pubkey.clone(),
        },
        confirmations: 1,
    }
}

fn destination() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([3; 20]))
}

// Independent BIP143 preimage construction, deliberately not SighashCache.
fn signature_hash(
    tx: &Transaction,
    input: usize,
    prevout: &TxOut,
    script_code: &bitcoin::Script,
) -> [u8; 32] {
    use bitcoin::{consensus::encode::serialize, hashes::sha256d};
    let mut preimage = serialize(&tx.version);
    let outpoints: Vec<u8> = tx
        .input
        .iter()
        .flat_map(|i| serialize(&i.previous_output))
        .collect();
    preimage.extend(sha256d::Hash::hash(&outpoints).to_byte_array());
    let sequences: Vec<u8> = tx
        .input
        .iter()
        .flat_map(|i| serialize(&i.sequence))
        .collect();
    preimage.extend(sha256d::Hash::hash(&sequences).to_byte_array());
    preimage.extend(serialize(&tx.input[input].previous_output));
    preimage.extend(serialize(&script_code.to_owned()));
    preimage.extend(serialize(&prevout.value.to_sat()));
    preimage.extend(serialize(&tx.input[input].sequence));
    let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
    preimage.extend(sha256d::Hash::hash(&outputs).to_byte_array());
    preimage.extend(serialize(&tx.lock_time));
    preimage.extend(serialize(&1u32));
    sha256d::Hash::hash(&preimage).to_byte_array()
}

#[tokio::test]
async fn scanner_to_signed_sweep_both_kinds_and_mixed() {
    let keys = RecoveryKeys::from_ldk_seed(&[42; 32]).unwrap();
    for indices in [vec![0], vec![1999], vec![0, 1, 1998, 1999]] {
        let outputs: Vec<_> = indices.iter().map(|&n| found(&keys, n, 100_000)).collect();
        let mut source = outputs.clone();
        let mut foreign = found(&keys, 33, 1_000_000);
        foreign.txout.script_pubkey = destination();
        source.push(foreign);
        let scanned = MemoryScanner(source).scan(keys.scripts()).await.unwrap();
        let rate = FeeRate::from_sat_per_vb(5).unwrap();
        let sweep = keys.build_sweep(&scanned, destination(), rate).unwrap();
        let tx = &sweep.transaction;
        assert_eq!(tx.version, transaction::Version::TWO);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].script_pubkey, destination());
        assert_eq!(
            tx.output[0].value.to_sat() + sweep.fee.to_sat(),
            100_000 * indices.len() as u64
        );
        assert!(sweep.fee >= rate.fee_wu(tx.weight()).unwrap());
        // These fixed signatures are at most two bytes below the size estimate.
        assert!(
            sweep.fee.to_sat() - rate.fee_wu(tx.weight()).unwrap().to_sat()
                <= 3 * indices.len() as u64
        );
        assert_eq!(tx.input.len(), outputs.len());
        let prevouts: Vec<_> = outputs.iter().map(|o| o.txout.clone()).collect();
        for (i, (&n, output)) in indices.iter().zip(&outputs).enumerate() {
            let input = &tx.input[i];
            let interpreter = miniscript::Interpreter::from_txdata(
                &output.txout.script_pubkey,
                &input.script_sig,
                &input.witness,
                input.sequence,
                tx.lock_time,
            )
            .unwrap();
            let secp = Secp256k1::verification_only();
            interpreter
                .iter(&secp, tx, i, &bitcoin::sighash::Prevouts::All(&prevouts))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            if n % 2 == 1 {
                // Isolate CSV evaluation: the positive path above verifies real
                // signatures; here signature verification is skipped so an invalid
                // sequence cannot merely fail because it changes the sighash.
                let immature = miniscript::Interpreter::from_txdata(
                    &output.txout.script_pubkey,
                    &input.script_sig,
                    &input.witness,
                    Sequence::ZERO,
                    tx.lock_time,
                )
                .unwrap();
                assert!(matches!(
                    immature.iter_assume_sigs().collect::<Result<Vec<_>, _>>(),
                    Err(miniscript::interpreter::Error::RelativeLockTimeNotMet(_))
                ));
                let disabled = miniscript::Interpreter::from_txdata(
                    &output.txout.script_pubkey,
                    &input.script_sig,
                    &input.witness,
                    Sequence::MAX,
                    tx.lock_time,
                )
                .unwrap();
                assert!(matches!(
                    disabled.iter_assume_sigs().collect::<Result<Vec<_>, _>>(),
                    Err(miniscript::interpreter::Error::RelativeLockTimeDisabled(_))
                ));
            }
            assert_eq!(input.previous_output, output.outpoint);
            assert!(input.script_sig.is_empty());
            let witness: Vec<_> = input.witness.iter().collect();
            assert_eq!(witness.len(), 2);
            let sig = bitcoin::ecdsa::Signature::from_slice(witness[0]).unwrap();
            assert_eq!(sig.sighash_type, EcdsaSighashType::All);
            let (public, script_code) = if n % 2 == 0 {
                assert_eq!(input.sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
                let pk = bitcoin::PublicKey::from_slice(witness[1]).unwrap();
                assert_eq!(
                    ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
                    output.txout.script_pubkey
                );
                (pk.inner, ScriptBuf::new_p2pkh(&pk.pubkey_hash()))
            } else {
                assert_eq!(input.sequence, Sequence::from_height(1));
                let script = ScriptBuf::from_bytes(witness[1].to_vec());
                assert_eq!(script.to_p2wsh(), output.txout.script_pubkey);
                assert_eq!(script.len(), 37);
                assert_eq!(script.as_bytes()[0], 33);
                assert_eq!(&script.as_bytes()[34..], &[0xad, 0x51, 0xb2]);
                (
                    bitcoin::secp256k1::PublicKey::from_slice(&script.as_bytes()[1..34]).unwrap(),
                    script,
                )
            };
            let hash = signature_hash(tx, i, &output.txout, &script_code);
            let secp = Secp256k1::verification_only();
            secp.verify_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(hash),
                &sig.signature,
                &public,
            )
            .unwrap();
            let mut tampered = tx.clone();
            tampered.output[0].value = Amount::from_sat(1);
            assert!(interpreter
                .iter(
                    &secp,
                    &tampered,
                    i,
                    &bitcoin::sighash::Prevouts::All(&prevouts)
                )
                .collect::<Result<Vec<_>, _>>()
                .is_err());
            let mut wrong_amounts = prevouts.clone();
            wrong_amounts[i].value = Amount::from_sat(output.txout.value.to_sat() + 1);
            assert!(interpreter
                .iter(
                    &secp,
                    tx,
                    i,
                    &bitcoin::sighash::Prevouts::All(&wrong_amounts)
                )
                .collect::<Result<Vec<_>, _>>()
                .is_err());
            let hash = signature_hash(&tampered, i, &output.txout, &script_code);
            assert!(secp
                .verify_ecdsa(
                    &bitcoin::secp256k1::Message::from_digest(hash),
                    &sig.signature,
                    &public
                )
                .is_err());
        }
    }
}

#[test]
fn rejects_unsafe_or_uneconomic_sweeps() {
    let keys = RecoveryKeys::from_ldk_seed(&[42; 32]).unwrap();
    let output = found(&keys, 1, 100_000);
    let rate = FeeRate::from_sat_per_vb(1).unwrap();
    let build = |outputs: &[FoundOutput]| keys.build_sweep(outputs, destination(), rate);
    assert!(matches!(build(&[]), Err(RecoveryError::NoOutputs)));
    assert!(matches!(
        build(&[output.clone(), output.clone()]),
        Err(RecoveryError::DuplicateOutpoint)
    ));
    let mut bad = output.clone();
    bad.txout.script_pubkey = destination();
    assert!(matches!(build(&[bad]), Err(RecoveryError::UnknownScript)));
    for n in [0, 1] {
        let mut bad = found(&keys, n, 100_000);
        bad.confirmations = 0;
        assert!(matches!(
            build(&[bad]),
            Err(RecoveryError::UnconfirmedOutput)
        ));
    }
    assert!(matches!(
        build(&[found(&keys, 1, 0)]),
        Err(RecoveryError::InvalidAmount)
    ));
    assert!(matches!(
        build(&[found(&keys, 1, u64::MAX)]),
        Err(RecoveryError::InvalidAmount)
    ));
    assert!(matches!(
        build(&[found(&keys, 1, 1)]),
        Err(RecoveryError::InsufficientFunds)
    ));
    assert!(matches!(
        build(&[found(&keys, 1, 400)]),
        Err(RecoveryError::DustOutput)
    ));
    assert!(matches!(
        keys.build_sweep(std::slice::from_ref(&output), destination(), FeeRate::ZERO),
        Err(RecoveryError::ZeroFeeRate)
    ));
    assert!(matches!(
        keys.build_sweep(
            std::slice::from_ref(&output),
            destination(),
            FeeRate::from_sat_per_kwu(u64::MAX)
        ),
        Err(RecoveryError::FeeOverflow)
    ));
    assert!(matches!(
        keys.build_sweep(&[output], ScriptBuf::new(), rate),
        Err(RecoveryError::InvalidDestination)
    ));
    assert!(matches!(
        build(&[
            found(&keys, 0, Amount::MAX_MONEY.to_sat()),
            found(&keys, 1, 1)
        ]),
        Err(RecoveryError::InvalidAmount)
    ));
}

#[test]
fn public_vectors_first_and_last_key() {
    // Independently calculated with Python hmac/SHA512 BIP32 CKDpriv and
    // cryptography/OpenSSL secp256k1 (seed [42;32], m/8'/i'). No secret fixtures.
    let keys = RecoveryKeys::from_ldk_seed(&[42; 32]).unwrap();
    for (index, p2wpkh, p2wsh) in [
        (
            0,
            "0014a7979029640c53a6fc3c2d652492395a834458f6",
            "0020c521e12eaf08007142d2d003e05ad3fbd923bcf70df909c75c2e8d2102b7ae26",
        ),
        (
            999,
            "001495041aabf99041e30e11b9fa74507a8ba387cd84",
            "0020af1e9fb930bac1b295c11a6370bffb4abe9a25267bb08f0a636a3d9ef1987751",
        ),
    ] {
        assert_eq!(
            hex::encode(keys.scripts()[index * 2].script_pubkey.as_bytes()),
            p2wpkh
        );
        assert_eq!(
            hex::encode(keys.scripts()[index * 2 + 1].script_pubkey.as_bytes()),
            p2wsh
        );
        assert_eq!(keys.scripts()[index * 2].key_index, index as u32);
        assert_eq!(
            keys.scripts()[index * 2 + 1].kind,
            OutputKind::AnchorToRemote
        );
    }
    let unique: std::collections::HashSet<_> =
        keys.scripts().iter().map(|s| &s.script_pubkey).collect();
    assert_eq!(unique.len(), 2000);
}

#[test]
fn fees_include_compactsize_input_count_and_standard_weight_limit() {
    let keys = RecoveryKeys::from_ldk_seed(&[42; 32]).unwrap();
    let rate = FeeRate::from_sat_per_vb(2).unwrap();
    for count in [252, 253] {
        let outputs: Vec<_> = (0..count).map(|n| found(&keys, n, 100_000)).collect();
        let sweep = keys.build_sweep(&outputs, destination(), rate).unwrap();
        assert!(sweep.fee >= rate.fee_wu(sweep.transaction.weight()).unwrap());
        assert_eq!(sweep.transaction.input.len(), count);
    }
    let outputs: Vec<_> = (0..2000).map(|n| found(&keys, n, 100_000)).collect();
    assert!(matches!(
        keys.build_sweep(&outputs, destination(), rate),
        Err(RecoveryError::TooHeavy)
    ));
}
