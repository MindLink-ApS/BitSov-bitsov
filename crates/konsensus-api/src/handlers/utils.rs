//! Shared utilities for API handlers.

use sha2::{Digest, Sha256};

/// Generate a synthetic payment proof (preimage + hash).
///
/// Used for:
/// - Zero-price control messages (kind 0) that don't require real payment
/// - Server response envelopes (web manifest, page response) where the
///   requester already paid for the request
///
/// **NOT** a fallback for Lightning unavailability — if Lightning is down,
/// the compose handler returns an error (fail-closed, Principle 2).
///
/// The proof is cryptographically valid: SHA256(preimage) == hash.
///
/// Returns: (hash, preimage, amount_msat)
pub fn generate_valid_proof(amount_msat: u64) -> ([u8; 32], [u8; 32], u64) {
    use rand::RngCore;
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    (hash, preimage, amount_msat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_valid_proof_hash_matches_preimage() {
        let (hash, preimage, amount) = generate_valid_proof(25);
        let expected_hash: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(hash, expected_hash);
        assert_eq!(amount, 25);
    }

    #[test]
    fn generate_valid_proof_zero_amount() {
        let (hash, preimage, amount) = generate_valid_proof(0);
        let expected_hash: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(hash, expected_hash);
        assert_eq!(amount, 0);
    }

    #[test]
    fn generate_valid_proof_large_amount() {
        let (hash, preimage, amount) = generate_valid_proof(u64::MAX);
        let expected_hash: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(hash, expected_hash);
        assert_eq!(amount, u64::MAX);
    }

    #[test]
    fn generate_valid_proof_unique_preimages() {
        let (_, p1, _) = generate_valid_proof(10);
        let (_, p2, _) = generate_valid_proof(10);
        // Cryptographic randomness — two calls should produce different preimages
        // (probability of collision: 2^-256)
        assert_ne!(p1, p2);
    }

    #[test]
    fn generate_valid_proof_preimage_not_zero() {
        let (_, preimage, _) = generate_valid_proof(10);
        // Random bytes should not be all zeros (probability 2^-256)
        assert_ne!(preimage, [0u8; 32]);
    }

    #[test]
    fn generate_valid_proof_hash_not_equal_preimage() {
        let (hash, preimage, _) = generate_valid_proof(10);
        // SHA256(x) != x for any x (with overwhelming probability)
        assert_ne!(hash, preimage);
    }
}
