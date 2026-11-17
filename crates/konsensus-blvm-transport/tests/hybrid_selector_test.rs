//! T-A.1: hybrid transport prefers direct Noise, falls back to mesh.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use konsensus_blvm_transport::{HybridBlvmTransport, MeshFallback, BITSOV_MESH_PROTOCOL_ID};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};

struct MockDirect {
    connected: bool,
    send_count: Arc<AtomicUsize>,
}

#[async_trait]
impl MessageTransport for MockDirect {
    async fn send(&self, _peer: &NodeId, _envelope: &UkmEnvelope) -> Result<(), TransportError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        Err(TransportError::Other("not implemented".into()))
    }

    async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
        Ok(())
    }

    async fn disconnect(&self, _peer: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }

    async fn is_connected(&self, _peer: &NodeId) -> bool {
        self.connected
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![]
    }
}

struct MockMesh {
    send_count: Arc<AtomicUsize>,
    last_protocol: Arc<std::sync::Mutex<Option<String>>>,
}

#[async_trait]
impl MeshFallback for MockMesh {
    async fn send_via_mesh(
        &self,
        _destination: &NodeId,
        _payload: &[u8],
        protocol_id: &str,
        _route_payment: Option<konsensus_blvm_payment::MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        *self.last_protocol.lock().unwrap() = Some(protocol_id.to_string());
        Ok(())
    }
}

fn test_envelope() -> UkmEnvelope {
    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);
    let proof = PaymentProof::new([3u8; 32], [4u8; 32], 1000);
    UkmEnvelope {
        id: MessageId::from_bytes([5u8; 32]),
        kind: 1,
        sender,
        recipient: Recipient::Node(recipient),
        timestamp: 1,
        ciphertext: b"hello".to_vec(),
        payment_proof: proof.into(),
        signature: Signature::from_bytes([6u8; 64]),
        nonce: Nonce::from_bytes([7u8; 24]),
        references: vec![],
    }
}

#[tokio::test]
async fn hybrid_prefers_direct_when_connected() {
    let direct_sends = Arc::new(AtomicUsize::new(0));
    let mesh_sends = Arc::new(AtomicUsize::new(0));
    let direct = Arc::new(MockDirect {
        connected: true,
        send_count: direct_sends.clone(),
    });
    let mesh = Arc::new(MockMesh {
        send_count: mesh_sends.clone(),
        last_protocol: Arc::new(std::sync::Mutex::new(None)),
    });
    let transport = HybridBlvmTransport::new(direct, mesh);

    let peer = NodeId::from_bytes([2u8; 32]);
    transport.send(&peer, &test_envelope()).await.unwrap();

    assert_eq!(direct_sends.load(Ordering::SeqCst), 1);
    assert_eq!(mesh_sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn hybrid_falls_back_to_mesh_when_not_connected() {
    let direct_sends = Arc::new(AtomicUsize::new(0));
    let mesh_sends = Arc::new(AtomicUsize::new(0));
    let last_protocol = Arc::new(std::sync::Mutex::new(None));
    let direct = Arc::new(MockDirect {
        connected: false,
        send_count: direct_sends.clone(),
    });
    let mesh = Arc::new(MockMesh {
        send_count: mesh_sends.clone(),
        last_protocol: last_protocol.clone(),
    });
    let transport = HybridBlvmTransport::new(direct, mesh);

    let peer = NodeId::from_bytes([2u8; 32]);
    transport.send(&peer, &test_envelope()).await.unwrap();

    assert_eq!(direct_sends.load(Ordering::SeqCst), 0);
    assert_eq!(mesh_sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        last_protocol.lock().unwrap().as_deref(),
        Some(BITSOV_MESH_PROTOCOL_ID)
    );
}
