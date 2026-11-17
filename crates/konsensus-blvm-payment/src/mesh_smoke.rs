//! Encode/decode helpers for manual mesh RPC smoke tests (Phase 0.7).

use crate::{MeshRoutePayment, MeshSendPacketRequest};

const BITSOV_PROTOCOL: &str = "bitsov-ukm-v1";

/// Build hex `request_hex` for blvm-node `meshsendpacket` RPC.
pub fn mesh_send_request_hex(
    destination: [u8; 32],
    payload: &[u8],
    route_payment: Option<MeshRoutePayment>,
) -> String {
    let request = MeshSendPacketRequest {
        destination,
        payload: payload.to_vec(),
        payment_proof: route_payment,
        protocol_id: Some(BITSOV_PROTOCOL.into()),
        ttl: Some(3600),
    };
    hex::encode(bincode::serialize(&request).expect("serialize SendPacketRequest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_send_request_hex_is_non_empty_and_roundtrips() {
        let hex_str = mesh_send_request_hex([2u8; 32], b"ping", None);
        assert!(!hex_str.is_empty());
        let bytes = hex::decode(&hex_str).unwrap();
        let req: MeshSendPacketRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(req.destination, [2u8; 32]);
        assert_eq!(req.payload, b"ping");
        assert_eq!(req.protocol_id.as_deref(), Some(BITSOV_PROTOCOL));
    }
}
