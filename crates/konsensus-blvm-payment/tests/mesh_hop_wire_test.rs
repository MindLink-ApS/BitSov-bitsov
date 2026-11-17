//! End-to-end mesh hop payment wire encoding for blvm-mesh RPC.

use konsensus_blvm_payment::{MeshRoutePayment, MeshSendPacketRequest};

#[test]
fn send_packet_request_with_lightning_hop_proof_bincode_roundtrip() {
    let req = MeshSendPacketRequest {
        destination: [0xAB; 32],
        payload: b"bitsov-ukm-v2-payload".to_vec(),
        payment_proof: Some(MeshRoutePayment::Lightning {
            invoice: "lnbcrt1000n1mock".into(),
            preimage: [0xCD; 32],
            amount_msats: 1000,
            timestamp: 1_700_000_000,
            expires_at: 1_700_003_600,
        }),
        protocol_id: Some("bitsov-ukm-v2".into()),
        ttl: Some(3600),
    };
    let bytes = bincode::serialize(&req).unwrap();
    let decoded: MeshSendPacketRequest = bincode::deserialize(&bytes).unwrap();
    assert_eq!(decoded.destination, req.destination);
    assert_eq!(decoded.payload, req.payload);
    match decoded.payment_proof {
        Some(MeshRoutePayment::Lightning {
            amount_msats,
            preimage,
            ..
        }) => {
            assert_eq!(amount_msats, 1000);
            assert_eq!(preimage, [0xCD; 32]);
        }
        _ => panic!("expected lightning hop proof"),
    }
}

#[test]
fn send_packet_request_none_proof_for_open_relay() {
    let req = MeshSendPacketRequest {
        destination: [0x01; 32],
        payload: b"open-relay".to_vec(),
        payment_proof: None,
        protocol_id: Some("bitsov-ukm-v1".into()),
        ttl: Some(3600),
    };
    let bytes = bincode::serialize(&req).unwrap();
    let decoded: MeshSendPacketRequest = bincode::deserialize(&bytes).unwrap();
    assert!(decoded.payment_proof.is_none());
}
