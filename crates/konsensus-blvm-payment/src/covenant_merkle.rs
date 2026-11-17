//! Extract CTV template hash from serialized covenant proofs for mesh merkle fields.

use serde_json::Value;

/// Build mesh `merkle_proof` from a serialized covenant proof.
///
/// blvm-mesh treats an empty merkle path as valid today; when present we attach the
/// CTV `template_hash` as a single 32-byte root commitment (future batch proofs may
/// append sibling hashes).
pub fn merkle_proof_from_covenant(covenant_proof: &[u8]) -> Vec<[u8; 32]> {
    extract_template_hash(covenant_proof)
        .map(|hash| vec![hash])
        .unwrap_or_default()
}

fn extract_template_hash(covenant_proof: &[u8]) -> Option<[u8; 32]> {
    if let Ok(value) = serde_json::from_slice::<Value>(covenant_proof) {
        if let Some(hash) = value.get("template_hash").and_then(parse_hash_32) {
            return Some(hash);
        }
    }

    // Bincode layout from blvm-node / blvm-mesh: template_hash is the first field.
    if covenant_proof.len() >= 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&covenant_proof[..32]);
        if hash != [0u8; 32] {
            return Some(hash);
        }
    }

    None
}

fn parse_hash_32(value: &Value) -> Option<[u8; 32]> {
    match value {
        Value::Array(items) if items.len() == 32 => {
            let mut hash = [0u8; 32];
            for (i, item) in items.iter().enumerate() {
                hash[i] = item.as_u64()? as u8;
            }
            Some(hash)
        }
        Value::String(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            Some(hash)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_template_hash_from_json_covenant() {
        let mut hash = [0xAB; 32];
        hash[0] = 0x01;
        let json = serde_json::json!({
            "template_hash": hash,
            "payment_request_id": "req-1",
            "created_at": 1,
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let merkle = merkle_proof_from_covenant(&bytes);
        assert_eq!(merkle, vec![hash]);
    }

    #[test]
    fn extracts_template_hash_from_hex_string_json() {
        let hash = [0xCD; 32];
        let json = serde_json::json!({
            "template_hash": hex::encode(hash),
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        assert_eq!(merkle_proof_from_covenant(&bytes), vec![hash]);
    }

    #[test]
    fn extracts_template_hash_from_bincode_prefix() {
        let hash = [0x42; 32];
        assert_eq!(merkle_proof_from_covenant(&hash), vec![hash]);
    }

    #[test]
    fn empty_when_unrecognized() {
        assert!(merkle_proof_from_covenant(b"not-a-proof").is_empty());
        assert!(merkle_proof_from_covenant(&[0u8; 32]).is_empty());
    }
}
