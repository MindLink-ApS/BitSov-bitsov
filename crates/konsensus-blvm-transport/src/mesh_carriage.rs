//! Mesh carriage encryption keys (X25519 ECDH + AEAD).

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use konsensus_core::traits::transport::TransportError;
use x25519_dalek::{PublicKey, StaticSecret};

const CARRIAGE_CONTEXT: &str = "bitsov-mesh-carriage-v1";
const NONCE_LEN: usize = 12;

/// Derive symmetric mesh carriage key from X25519 ECDH shared secret.
pub fn mesh_carriage_key(
    local_x25519_secret: &[u8; 32],
    peer_x25519_public: &[u8; 32],
) -> [u8; 32] {
    let secret = StaticSecret::from(*local_x25519_secret);
    let public = PublicKey::from(*peer_x25519_public);
    let shared = secret.diffie_hellman(&public);
    blake3::derive_key(CARRIAGE_CONTEXT, shared.as_bytes())
}

/// Encrypt plaintext for mesh v2 carriage.
pub fn mesh_carriage_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| TransportError::Other(format!("aead key: {e}")))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: b"bitsov-ukm-v2",
            },
        )
        .map_err(|e| TransportError::Other(format!("encrypt: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt mesh v2 carriage ciphertext (nonce || ciphertext).
pub fn mesh_carriage_decrypt(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
    if bytes.len() <= NONCE_LEN {
        return Err(TransportError::WireProtocol("v2 payload too short".into()));
    }
    let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| TransportError::Other(format!("aead key: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: b"bitsov-ukm-v2",
            },
        )
        .map_err(|e| TransportError::WireProtocol(format!("v2 decrypt failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn carriage_encrypt_roundtrip() {
        let alice_secret = StaticSecret::from([1u8; 32]);
        let bob_secret = StaticSecret::from([2u8; 32]);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_sk = alice_secret.to_bytes();
        let bob_sk = bob_secret.to_bytes();
        let key = mesh_carriage_key(&alice_sk, bob_public.as_bytes());
        let ct = mesh_carriage_encrypt(&key, b"ukm-bytes").unwrap();
        let key_bob = mesh_carriage_key(&bob_sk, alice_public.as_bytes());
        assert_eq!(key, key_bob);
        let pt = mesh_carriage_decrypt(&key_bob, &ct).unwrap();
        assert_eq!(pt, b"ukm-bytes");
    }
}
