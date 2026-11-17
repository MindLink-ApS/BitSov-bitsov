//! Hybrid transport mesh hop payment tests.

use std::sync::Arc;

use async_trait::async_trait;
use konsensus_blvm_payment::{MeshHopPaymentAcquirer, MeshHopPolicy, MeshRoutePayment};
use konsensus_blvm_transport::{HybridBlvmTransport, MeshFallback, MeshHopSendConfig};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_message::Frame;

struct MockDirect {
    connected: bool,
}

#[async_trait]
impl MessageTransport for MockDirect {
    async fn send(&self, _peer: &NodeId, _envelope: &UkmEnvelope) -> Result<(), TransportError> {
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
    last_had_payment: Arc<std::sync::Mutex<Option<bool>>>,
}

#[async_trait]
impl MeshFallback for MockMesh {
    async fn send_via_mesh(
        &self,
        _destination: &NodeId,
        _payload: &[u8],
        _protocol_id: &str,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        *self.last_had_payment.lock().unwrap() = Some(route_payment.is_some());
        Ok(())
    }
}

struct FixedHopAcquirer;

#[async_trait]
impl MeshHopPaymentAcquirer for FixedHopAcquirer {
    async fn acquire_hop_payment(
        &self,
        _destination: [u8; 32],
        amount_msat: u64,
    ) -> Result<MeshRoutePayment, konsensus_blvm_payment::MeshHopError> {
        Ok(MeshRoutePayment::Lightning {
            invoice: "lnbc1mock".into(),
            preimage: [0xCD; 32],
            amount_msats: amount_msat,
            timestamp: 1,
            expires_at: 9999,
        })
    }
}

fn lightning_envelope() -> UkmEnvelope {
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
        payment_proof: GatePaymentProof::Lightning(proof),
        signature: Signature::from_bytes([6u8; 64]),
        nonce: Nonce::from_bytes([7u8; 24]),
        references: vec![],
    }
}

#[tokio::test]
async fn mesh_fallback_attaches_hop_payment_for_lightning_gate() {
    let last_had_payment = Arc::new(std::sync::Mutex::new(None));
    let direct = Arc::new(MockDirect { connected: false });
    let mesh = Arc::new(MockMesh {
        last_had_payment: last_had_payment.clone(),
    });
    let transport = HybridBlvmTransport::new(direct, mesh).with_mesh_hop(MeshHopSendConfig {
        payment_required: true,
        hop_msat: 1000,
        control_hop_msat: 1000,
        hop_policy: MeshHopPolicy::PerSend,
        acquirer: Arc::new(FixedHopAcquirer),
    });

    let peer = NodeId::from_bytes([2u8; 32]);
    transport.send(&peer, &lightning_envelope()).await.unwrap();

    assert_eq!(*last_had_payment.lock().unwrap(), Some(true));
}

#[tokio::test]
async fn mesh_fallback_open_relay_without_hop_config() {
    let last_had_payment = Arc::new(std::sync::Mutex::new(None));
    let direct = Arc::new(MockDirect { connected: false });
    let mesh = Arc::new(MockMesh {
        last_had_payment: last_had_payment.clone(),
    });
    let transport = HybridBlvmTransport::new(direct, mesh);

    let peer = NodeId::from_bytes([2u8; 32]);
    transport.send(&peer, &lightning_envelope()).await.unwrap();
    assert_eq!(*last_had_payment.lock().unwrap(), Some(false));
}

#[tokio::test]
async fn mesh_control_frame_attaches_hop_payment() {
    let last_had_payment = Arc::new(std::sync::Mutex::new(None));
    let direct = Arc::new(MockDirect { connected: false });
    let mesh = Arc::new(MockMesh {
        last_had_payment: last_had_payment.clone(),
    });
    let transport = HybridBlvmTransport::new(direct, mesh).with_mesh_hop(MeshHopSendConfig {
        payment_required: true,
        hop_msat: 1000,
        control_hop_msat: 500,
        hop_policy: MeshHopPolicy::PerSend,
        acquirer: Arc::new(FixedHopAcquirer),
    });

    let peer = NodeId::from_bytes([2u8; 32]);
    let frame = konsensus_message::Frame::MessageAck {
        id: MessageId::from_bytes([8u8; 32]),
        duplicate: false,
        paid_until_ms: None,
    };
    transport
        .send_raw_frame(&peer, &frame.to_bytes().unwrap())
        .await
        .unwrap();

    assert_eq!(*last_had_payment.lock().unwrap(), Some(true));
}

#[tokio::test]
async fn mesh_fallback_fail_closed_when_payment_required() {
    let direct = Arc::new(MockDirect { connected: false });
    let mesh = Arc::new(MockMesh {
        last_had_payment: Arc::new(std::sync::Mutex::new(None)),
    });
    let transport = HybridBlvmTransport::new(direct, mesh).with_mesh_hop(MeshHopSendConfig {
        payment_required: true,
        hop_msat: 1000,
        control_hop_msat: 1000,
        hop_policy: MeshHopPolicy::Disabled,
        acquirer: Arc::new(FixedHopAcquirer),
    });

    let peer = NodeId::from_bytes([2u8; 32]);
    let err = transport
        .send(&peer, &lightning_envelope())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("hop payment"));
}

#[tokio::test]
async fn blvm_gate_proof_skips_hop_acquirer() {
    let last_had_payment = Arc::new(std::sync::Mutex::new(None));
    let direct = Arc::new(MockDirect { connected: false });
    let mesh = Arc::new(MockMesh {
        last_had_payment: last_had_payment.clone(),
    });
    let transport = HybridBlvmTransport::new(direct, mesh)
        .with_mesh_ctv(true)
        .with_mesh_hop(MeshHopSendConfig {
        payment_required: true,
        hop_msat: 1000,
        control_hop_msat: 1000,
        hop_policy: MeshHopPolicy::PerSend,
        acquirer: Arc::new(FixedHopAcquirer),
    });

    let sender = NodeId::from_bytes([1u8; 32]);
    let recipient = NodeId::from_bytes([2u8; 32]);
    let envelope = UkmEnvelope {
        id: MessageId::from_bytes([5u8; 32]),
        kind: 1,
        sender,
        recipient: Recipient::Node(recipient),
        timestamp: 1,
        ciphertext: b"hello".to_vec(),
        payment_proof: GatePaymentProof::BlvmCovenant {
            covenant_proof: vec![0x01, 0x02],
            output_index: 0,
            amount_sats: 10,
            timestamp: 1,
        },
        signature: Signature::from_bytes([6u8; 64]),
        nonce: Nonce::from_bytes([7u8; 24]),
        references: vec![],
    };

    transport.send(&recipient, &envelope).await.unwrap();
    assert_eq!(*last_had_payment.lock().unwrap(), Some(true));
}
