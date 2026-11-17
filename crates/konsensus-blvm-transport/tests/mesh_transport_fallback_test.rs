//! MeshSenderFallback delegates to MeshPacketSender.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use konsensus_blvm_payment::MeshRoutePayment;
use konsensus_blvm_transport::{
    MeshFallback, MeshPacketSender, MeshSenderFallback, BITSOV_MESH_PROTOCOL_ID,
};
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;

struct RecordingSender {
    last_dest: Mutex<Option<[u8; 32]>>,
    last_payload: Mutex<Option<Vec<u8>>>,
    last_protocol: Mutex<Option<String>>,
    last_payment: Mutex<Option<MeshRoutePayment>>,
}

#[async_trait]
impl MeshPacketSender for RecordingSender {
    async fn send_mesh_packet(
        &self,
        destination: [u8; 32],
        payload: Vec<u8>,
        protocol_id: String,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        *self.last_dest.lock().unwrap() = Some(destination);
        *self.last_payload.lock().unwrap() = Some(payload);
        *self.last_protocol.lock().unwrap() = Some(protocol_id);
        *self.last_payment.lock().unwrap() = route_payment;
        Ok(())
    }
}

#[tokio::test]
async fn mesh_sender_fallback_forwards_to_packet_sender() {
    let recorder = Arc::new(RecordingSender {
        last_dest: Mutex::new(None),
        last_payload: Mutex::new(None),
        last_protocol: Mutex::new(None),
        last_payment: Mutex::new(None),
    });
    let mesh = MeshSenderFallback::new(recorder.clone());

    let dest = NodeId::from_bytes([0xAB; 32]);
    let payload = b"ukm-bytes".to_vec();
    mesh.send_via_mesh(&dest, &payload, BITSOV_MESH_PROTOCOL_ID, None)
        .await
        .expect("send");

    assert_eq!(*recorder.last_dest.lock().unwrap(), Some([0xAB; 32]));
    assert_eq!(
        recorder.last_payload.lock().unwrap().as_deref(),
        Some(payload.as_slice())
    );
    assert_eq!(
        recorder.last_protocol.lock().unwrap().as_deref(),
        Some(BITSOV_MESH_PROTOCOL_ID)
    );
}

#[tokio::test]
async fn per_send_route_payment_overrides_stored_default() {
    let recorder = Arc::new(RecordingSender {
        last_dest: Mutex::new(None),
        last_payload: Mutex::new(None),
        last_protocol: Mutex::new(None),
        last_payment: Mutex::new(None),
    });
    let mesh = MeshSenderFallback::new(recorder.clone());
    mesh.set_route_payment(Some(MeshRoutePayment::Lightning {
        invoice: "stored".into(),
        preimage: [0x01; 32],
        amount_msats: 1,
        timestamp: 0,
        expires_at: 999,
    }));

    let per_send = MeshRoutePayment::Lightning {
        invoice: "per-send".into(),
        preimage: [0x02; 32],
        amount_msats: 1000,
        timestamp: 0,
        expires_at: 999,
    };
    let dest = NodeId::from_bytes([0xCD; 32]);
    mesh.send_via_mesh(&dest, b"x", BITSOV_MESH_PROTOCOL_ID, Some(per_send.clone()))
        .await
        .unwrap();

    assert_eq!(
        recorder.last_payment.lock().unwrap().as_ref(),
        Some(&per_send)
    );
}

#[tokio::test]
async fn stored_route_payment_used_when_per_send_none() {
    let recorder = Arc::new(RecordingSender {
        last_dest: Mutex::new(None),
        last_payload: Mutex::new(None),
        last_protocol: Mutex::new(None),
        last_payment: Mutex::new(None),
    });
    let stored = MeshRoutePayment::Lightning {
        invoice: "stored".into(),
        preimage: [0x01; 32],
        amount_msats: 1,
        timestamp: 0,
        expires_at: 999,
    };
    let mesh = MeshSenderFallback::with_route_payment(recorder.clone(), stored.clone());
    let dest = NodeId::from_bytes([0xCD; 32]);
    mesh.send_via_mesh(&dest, b"x", BITSOV_MESH_PROTOCOL_ID, None)
        .await
        .unwrap();

    assert_eq!(
        recorder.last_payment.lock().unwrap().as_ref(),
        Some(&stored)
    );
}
