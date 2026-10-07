//! Blind envelope: internal consensus txid bytes (not display-hex byte order).
use bitcoin::{consensus, hashes::Hash, Transaction, Txid};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_BLOB_BYTES: usize = 4096;

/// Only these fields cross the future transport boundary; no channel/peer identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedBlob {
    pub hint: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    pub fn encrypt(breach_txid: Txid, txs: &[Transaction]) -> io::Result<Self> {
        // BlobV1 = consensus u8 version followed by consensus Vec<Transaction>.
        let mut plaintext = vec![1];
        plaintext.extend(consensus::serialize(&txs.to_vec()));
        if plaintext.len() + 24 + 16 > MAX_BLOB_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tower blob too large",
            ));
        }
        let bytes = breach_txid.to_byte_array();
        let hint: [u8; 16] = bytes[..16].try_into().unwrap();
        let mut nonce = [0; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher =
            XChaCha20Poly1305::new(&blake3::derive_key("bitsov-tower-blob-v1", &bytes).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &hint,
                },
            )
            .map_err(|_| invalid_blob())?;
        Ok(Self {
            hint,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(&self, breach_txid: Txid) -> io::Result<Vec<Transaction>> {
        if self.ciphertext.len() + 24 > MAX_BLOB_BYTES {
            return Err(invalid_blob());
        }
        let cipher = XChaCha20Poly1305::new(
            &blake3::derive_key("bitsov-tower-blob-v1", &breach_txid.to_byte_array()).into(),
        );
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.hint,
                },
            )
            .map_err(|_| invalid_blob())?;
        if plaintext.first() != Some(&1) {
            return Err(invalid_blob());
        }
        consensus::deserialize(&plaintext[1..]).map_err(|_| invalid_blob())
    }
}

fn invalid_blob() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unauthenticated tower blob",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, hashes::Hash, transaction, Transaction};

    #[test]
    fn tower_blob_round_trip_and_random_nonce() {
        let txid = Txid::from_byte_array([7; 32]);
        let txs = vec![Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }];
        let a = SealedBlob::encrypt(txid, &txs).unwrap();
        let b = SealedBlob::encrypt(txid, &txs).unwrap();
        assert_eq!(a.hint, [7; 16]);
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.decrypt(txid).unwrap(), txs);
    }

    #[test]
    fn tower_blob_wrong_hint_full_key_nonce_or_ciphertext_fails_aead() {
        let txid = Txid::from_byte_array([7; 32]);
        let blob = SealedBlob::encrypt(txid, &[]).unwrap();
        let mut wrong_key = [7; 32];
        wrong_key[31] ^= 1; // Same hint, different full txid.
        assert!(blob.decrypt(Txid::from_byte_array(wrong_key)).is_err());
        let mut bad = blob.clone();
        bad.hint[0] ^= 1;
        assert!(bad.decrypt(txid).is_err());
        let mut bad = blob.clone();
        bad.nonce[0] ^= 1;
        assert!(bad.decrypt(txid).is_err());
        let mut bad = blob;
        bad.ciphertext[0] ^= 1;
        assert!(bad.decrypt(txid).is_err());
    }
}
