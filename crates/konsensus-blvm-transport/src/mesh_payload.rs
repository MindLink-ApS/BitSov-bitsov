//! UKM and control-frame serialization for blvm-mesh transport payloads.

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::traits::transport::TransportError;

use crate::mesh_carriage::{mesh_carriage_decrypt, mesh_carriage_encrypt, mesh_carriage_key};

/// Magic prefix for mesh-delivered Noise control frames (ACK/reject/price-table).
pub const MESH_CONTROL_MAGIC: &[u8] = b"bitsov-ctrl-v1";

/// Magic prefix for encrypted UKM on mesh (v2).
pub const MESH_UKM_V2_MAGIC: &[u8] = b"bitsov-ukm-v2";

/// Protocol id for encrypted UKM on blvm-mesh.
pub const BITSOV_MESH_PROTOCOL_ID_V2: &str = "bitsov-ukm-v2";

/// Max UKM JSON payload from mesh (mirrors blvm-mesh `MAX_BINCODE_PAYLOAD_SIZE`).
pub const MAX_MESH_UKM_BYTES: usize = 256 * 1024;

/// Max inner wire frame bytes inside a mesh control wrapper.
pub const MAX_MESH_CONTROL_FRAME_BYTES: usize = 64 * 1024;

/// UKM payload encoding preference on mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshPayloadMode {
    V1,
    V2,
    PreferV2,
}

impl MeshPayloadMode {
    pub fn from_config_str(s: &str) -> Self {
        match s {
            "v2" => Self::V2,
            "v1" => Self::V1,
            _ => Self::PreferV2,
        }
    }
}

/// Serialize a UKM envelope for mesh `MeshPacket.payload` (v1 JSON).
pub fn encode_ukm_v1(envelope: &UkmEnvelope) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(envelope).map_err(|e| TransportError::WireProtocol(e.to_string()))
}

/// Encode UKM for mesh with optional v2 encryption to peer X25519.
pub fn encode_ukm_for_mesh(
    envelope: &UkmEnvelope,
    mode: MeshPayloadMode,
    local_x25519_secret: &[u8; 32],
    peer_x25519: Option<[u8; 32]>,
) -> Result<(Vec<u8>, &'static str), TransportError> {
    let use_v2 = matches!(mode, MeshPayloadMode::V2)
        || (matches!(mode, MeshPayloadMode::PreferV2) && peer_x25519.is_some());

    if use_v2 {
        let peer_pk = peer_x25519.ok_or_else(|| {
            TransportError::Other("v2 mesh encoding requires peer X25519 from Hello".into())
        })?;
        let plaintext = encode_ukm_v1(envelope)?;
        let key = mesh_carriage_key(local_x25519_secret, &peer_pk);
        let encrypted = mesh_carriage_encrypt(&key, &plaintext)?;
        let mut out = MESH_UKM_V2_MAGIC.to_vec();
        out.extend_from_slice(&encrypted);
        if out.len() > MAX_MESH_UKM_BYTES {
            return Err(TransportError::WireProtocol(format!(
                "mesh v2 payload exceeds {MAX_MESH_UKM_BYTES} bytes"
            )));
        }
        return Ok((out, BITSOV_MESH_PROTOCOL_ID_V2));
    }

    let json = encode_ukm_v1(envelope)?;
    Ok((json, super::hybrid::BITSOV_MESH_PROTOCOL_ID))
}

/// Decode mesh UKM bytes (v1 JSON or v2 encrypted).
pub fn decode_mesh_ukm(
    bytes: &[u8],
    local_x25519_secret: &[u8; 32],
    peer_x25519: Option<[u8; 32]>,
) -> Result<UkmEnvelope, TransportError> {
    if bytes.len() > MAX_MESH_UKM_BYTES {
        return Err(TransportError::WireProtocol(format!(
            "mesh UKM payload exceeds {MAX_MESH_UKM_BYTES} bytes"
        )));
    }
    if bytes.starts_with(MESH_UKM_V2_MAGIC) {
        let peer_pk = peer_x25519.ok_or_else(|| {
            TransportError::WireProtocol("v2 mesh UKM requires peer X25519".into())
        })?;
        let key = mesh_carriage_key(local_x25519_secret, &peer_pk);
        let plaintext = mesh_carriage_decrypt(&key, &bytes[MESH_UKM_V2_MAGIC.len()..])?;
        return serde_json::from_slice(&plaintext)
            .map_err(|e| TransportError::WireProtocol(e.to_string()));
    }
    decode_ukm(bytes)
}

/// Serialize a UKM envelope for mesh (v1 compat alias).
pub fn encode_ukm(envelope: &UkmEnvelope) -> Result<Vec<u8>, TransportError> {
    encode_ukm_v1(envelope)
}

/// Decode a UKM envelope received from mesh (v1 JSON).
pub fn decode_ukm(bytes: &[u8]) -> Result<UkmEnvelope, TransportError> {
    if bytes.len() > MAX_MESH_UKM_BYTES {
        return Err(TransportError::WireProtocol(format!(
            "mesh UKM payload exceeds {MAX_MESH_UKM_BYTES} bytes"
        )));
    }
    serde_json::from_slice(bytes).map_err(|e| TransportError::WireProtocol(e.to_string()))
}

/// Wrap serialized wire `Frame` bytes for mesh fallback when direct Noise is unavailable.
pub fn encode_mesh_control_frame(frame_bytes: &[u8]) -> Vec<u8> {
    let len = u32::try_from(frame_bytes.len()).expect("frame fits in u32");
    let mut out = MESH_CONTROL_MAGIC.to_vec();
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(frame_bytes);
    out
}

/// Returns wire frame JSON bytes when `payload` is a mesh control wrapper.
pub fn try_decode_mesh_control_frame(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < MESH_CONTROL_MAGIC.len() + 4 {
        return None;
    }
    if &payload[..MESH_CONTROL_MAGIC.len()] != MESH_CONTROL_MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(
        payload[MESH_CONTROL_MAGIC.len()..MESH_CONTROL_MAGIC.len() + 4]
            .try_into()
            .ok()?,
    ) as usize;
    if len > MAX_MESH_CONTROL_FRAME_BYTES {
        return None;
    }
    let start = MESH_CONTROL_MAGIC.len() + 4;
    let end = start.checked_add(len)?;
    if end != payload.len() {
        return None;
    }
    Some(payload[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::kind::KIND_CHAT;
    use konsensus_core::types::{NodeId, PaymentProof, Recipient};
    use konsensus_core::UkmEnvelopeBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn sample_envelope() -> UkmEnvelope {
        let sender = NodeId::from_bytes([1u8; 32]);
        let recipient = NodeId::from_bytes([2u8; 32]);
        let proof = PaymentProof::new([3u8; 32], [4u8; 32], 1000);
        UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            Recipient::Node(recipient),
            b"cipher".to_vec(),
            proof,
        )
        .build()
    }

    #[test]
    fn mesh_control_frame_roundtrip() {
        let frame = br#"{"MessageAck":{"id":"abc"}}"#;
        let encoded = encode_mesh_control_frame(frame);
        assert_eq!(
            try_decode_mesh_control_frame(&encoded).as_deref(),
            Some(frame.as_slice())
        );
        assert!(try_decode_mesh_control_frame(b"not-a-control-frame").is_none());
    }

    #[test]
    fn v2_ukm_roundtrip() {
        let env = sample_envelope();
        let alice_secret = StaticSecret::from([5u8; 32]);
        let bob_secret = StaticSecret::from([6u8; 32]);
        let alice_sk = alice_secret.to_bytes();
        let bob_sk = bob_secret.to_bytes();
        let bob_pk = *PublicKey::from(&bob_secret).as_bytes();
        let alice_pk = *PublicKey::from(&alice_secret).as_bytes();
        let (bytes, proto) =
            encode_ukm_for_mesh(&env, MeshPayloadMode::V2, &alice_sk, Some(bob_pk)).unwrap();
        assert_eq!(proto, BITSOV_MESH_PROTOCOL_ID_V2);
        assert!(bytes.starts_with(MESH_UKM_V2_MAGIC));
        let decoded = decode_mesh_ukm(&bytes, &bob_sk, Some(alice_pk)).unwrap();
        assert_eq!(decoded.id, env.id);
    }

    #[test]
    fn oversized_mesh_control_frame_rejected() {
        let len = (MAX_MESH_CONTROL_FRAME_BYTES + 1) as u32;
        let mut payload = MESH_CONTROL_MAGIC.to_vec();
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend(vec![0u8; MAX_MESH_CONTROL_FRAME_BYTES + 1]);
        assert!(try_decode_mesh_control_frame(&payload).is_none());
    }

    #[test]
    fn oversized_ukm_rejected() {
        let huge = vec![b'{'; MAX_MESH_UKM_BYTES + 1];
        let err = decode_ukm(&huge).unwrap_err().to_string();
        assert!(err.contains("exceeds"));
    }
}
