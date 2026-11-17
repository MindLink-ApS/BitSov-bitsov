//! Full carriage path: Lightning gate UKM + hop payment → mesh send DTO.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use konsensus_blvm_payment::{LightningMeshHopAcquirer, MeshHopPolicy, MeshRoutePayment};
use konsensus_blvm_transport::{
    HybridBlvmTransport, MeshFallback, MeshHopSendConfig, MeshPayloadMode,
};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{NodeId, PaymentProof, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_lightning::MockLightningProvider;

struct MockDirect {
    connected: bool,
}

#[async_trait]
impl MessageTransport for MockDirect {
    async fn send(&self, _peer: &NodeId, _envelope: &UkmEnvelope) -> Result<(), TransportError> {
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        Err(TransportError::Other("n/a".into()))
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

struct CapturingMesh {
    last_payment: Arc<Mutex<Option<MeshRoutePayment>>>,
    last_protocol: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl MeshFallback for CapturingMesh {
    async fn send_via_mesh(
        &self,
        _destination: &NodeId,
        _payload: &[u8],
        protocol_id: &str,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        *self.last_payment.lock().unwrap() = route_payment;
        *self.last_protocol.lock().unwrap() = Some(protocol_id.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn lightning_ukm_mesh_fallback_acquires_real_hop_proof() {
    let sender = NodeId::from_bytes([0x11; 32]);
    let recipient = NodeId::from_bytes([0x22; 32]);
    let envelope = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        Recipient::Node(recipient),
        b"relay-carriage".to_vec(),
        GatePaymentProof::Lightning(PaymentProof::new([0xAA; 32], [0xBB; 32], 500)),
    )
    .build();

    let last_payment = Arc::new(Mutex::new(None));
    let last_protocol = Arc::new(Mutex::new(None));
    let mesh = Arc::new(CapturingMesh {
        last_payment: last_payment.clone(),
        last_protocol: last_protocol.clone(),
    });
    let ln = Arc::new(MockLightningProvider::new());
    let transport = HybridBlvmTransport::new(Arc::new(MockDirect { connected: false }), mesh)
        .with_mesh_encoding(MeshPayloadMode::PreferV2, [0x33; 32], {
            use konsensus_blvm_transport::RegistryMeshAddressBook;
            use konsensus_message::peer::{PeerEntry, PeerRegistry};
            use std::net::SocketAddr;
            use tokio::sync::RwLock;
            let mut reg = PeerRegistry::new();
            reg.add(PeerEntry {
                node_id: recipient,
                addr: SocketAddr::from(([127, 0, 0, 1], 9735)),
                label: None,
                auto_connect: false,
            });
            Arc::new(RegistryMeshAddressBook::new(
                Arc::new(RwLock::new(reg)),
                sender,
            ))
        })
        .with_mesh_hop(MeshHopSendConfig {
            payment_required: true,
            hop_msat: 1000,
            control_hop_msat: 1000,
            hop_policy: MeshHopPolicy::PerSend,
            acquirer: Arc::new(LightningMeshHopAcquirer::new(ln)),
        });

    transport.send(&recipient, &envelope).await.unwrap();

    let payment = last_payment.lock().unwrap().clone().expect("hop payment");
    assert!(matches!(payment, MeshRoutePayment::Lightning { .. }));
    let protocol = last_protocol.lock().unwrap().clone().expect("protocol");
    assert!(
        protocol == "bitsov-ukm-v2" || protocol == "bitsov-ukm-v1",
        "unexpected protocol {protocol}"
    );
}
