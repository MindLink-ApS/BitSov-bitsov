//! T-A.2: UKM round-trip over mesh payload encoding.

use konsensus_blvm_transport::{
    decode_ukm, encode_ukm, HybridBlvmTransport, MeshFallback, BITSOV_MESH_PROTOCOL_ID,
};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
use std::sync::{Arc, Mutex};

struct RecordingMesh {
    last_payload: Arc<Mutex<Option<Vec<u8>>>>,
    last_protocol: Arc<Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl MeshFallback for RecordingMesh {
    async fn send_via_mesh(
        &self,
        _destination: &NodeId,
        payload: &[u8],
        protocol_id: &str,
        _route_payment: Option<konsensus_blvm_payment::MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        *self.last_payload.lock().unwrap() = Some(payload.to_vec());
        *self.last_protocol.lock().unwrap() = Some(protocol_id.to_string());
        Ok(())
    }
}

struct OfflineDirect;

#[async_trait::async_trait]
impl MessageTransport for OfflineDirect {
    async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> {
        Ok(())
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        Err(TransportError::Other("offline".into()))
    }
    async fn connect(&self, _: &NodeId, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, _: &NodeId) -> bool {
        false
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![]
    }
}

fn sample_envelope() -> UkmEnvelope {
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);
    let proof = PaymentProof::new([3u8; 32], [4u8; 32], 1000);
    UkmEnvelope {
        id: MessageId::from_bytes([5u8; 32]),
        kind: 1,
        sender,
        recipient: Recipient::Node(recipient),
        timestamp: 1,
        ciphertext: b"encrypted-payload".to_vec(),
        payment_proof: proof.into(),
        signature: Signature::from_bytes([6u8; 64]),
        nonce: Nonce::from_bytes([7u8; 24]),
        references: vec![],
    }
}

#[tokio::test]
async fn ukm_mesh_payload_roundtrip() {
    let payload_store = Arc::new(Mutex::new(None));
    let protocol_store = Arc::new(Mutex::new(None));
    let mesh = Arc::new(RecordingMesh {
        last_payload: payload_store.clone(),
        last_protocol: protocol_store.clone(),
    });
    let transport = HybridBlvmTransport::new(Arc::new(OfflineDirect), mesh);

    let envelope = sample_envelope();
    let peer = NodeId::from_bytes([2u8; 32]);
    transport.send(&peer, &envelope).await.unwrap();

    let bytes = payload_store
        .lock()
        .unwrap()
        .clone()
        .expect("mesh payload stored");
    assert_eq!(
        protocol_store.lock().unwrap().as_deref(),
        Some(BITSOV_MESH_PROTOCOL_ID)
    );

    let decoded = decode_ukm(&bytes).expect("decode mesh payload");
    assert_eq!(decoded, envelope);

    let reencoded = encode_ukm(&decoded).unwrap();
    assert_eq!(reencoded, bytes);
}
