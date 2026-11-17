//! Integration tests for mesh identity binding, v2 privacy, and address book routing.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use konsensus_blvm_transport::{
    decode_mesh_ukm, encode_ukm_for_mesh, HybridBlvmTransport, MeshAddressBook, MeshFallback,
    MeshPayloadMode, MeshSenderFallback, RegistryMeshAddressBook, BITSOV_MESH_PROTOCOL_ID,
    BITSOV_MESH_PROTOCOL_ID_V2,
};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::kind::KIND_CHAT;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{NodeId, PaymentProof, Recipient};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_message::peer::{PeerEntry, PeerRegistry};
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

struct RecordingMesh {
    last_payload: Arc<Mutex<Option<Vec<u8>>>>,
    last_protocol: Arc<Mutex<Option<String>>>,
}

#[async_trait]
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

#[async_trait]
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

struct RecordingSender {
    last_dest: Mutex<Option<[u8; 32]>>,
}

#[async_trait]
impl konsensus_blvm_transport::MeshPacketSender for RecordingSender {
    async fn send_mesh_packet(
        &self,
        destination: [u8; 32],
        _payload: Vec<u8>,
        _protocol_id: String,
        _route_payment: Option<konsensus_blvm_payment::MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        *self.last_dest.lock().unwrap() = Some(destination);
        Ok(())
    }
}

fn sample_envelope(sender: NodeId, recipient: NodeId) -> UkmEnvelope {
    let proof = PaymentProof::new([3u8; 32], [4u8; 32], 1000);
    UkmEnvelopeBuilder::new(
        KIND_CHAT,
        sender,
        Recipient::Node(recipient),
        b"mesh-payload".to_vec(),
        proof,
    )
    .build()
}

fn address_book_with_peer(
    bitsov_byte: u8,
    mesh_byte: Option<u8>,
    x25519_byte: Option<u8>,
    local_byte: u8,
) -> Arc<dyn MeshAddressBook> {
    let mut reg = PeerRegistry::new();
    let bitsov = NodeId::from_bytes([bitsov_byte; 32]);
    reg.add(PeerEntry {
        node_id: bitsov,
        addr: SocketAddr::from(([127, 0, 0, 1], 9735)),
        label: None,
        auto_connect: false,
    });
    let mut bindings = std::collections::HashMap::new();
    if mesh_byte.is_some() || x25519_byte.is_some() {
        bindings.insert(
            bitsov,
            konsensus_blvm_transport::MeshPeerBinding {
                mesh_node_id: mesh_byte.map(|b| NodeId::from_bytes([b; 32])),
                peer_x25519: x25519_byte.map(|b| [b; 32]),
            },
        );
    }
    Arc::new(RegistryMeshAddressBook::with_bindings(
        Arc::new(RwLock::new(reg)),
        NodeId::from_bytes([local_byte; 32]),
        bindings,
    ))
}

#[tokio::test]
async fn hybrid_prefer_v2_uses_v1_without_peer_x25519() {
    let payload_store = Arc::new(Mutex::new(None));
    let protocol_store = Arc::new(Mutex::new(None));
    let mesh = Arc::new(RecordingMesh {
        last_payload: payload_store.clone(),
        last_protocol: protocol_store.clone(),
    });
    let book = address_book_with_peer(2, None, None, 1);
    let transport = HybridBlvmTransport::new(Arc::new(OfflineDirect), mesh).with_mesh_encoding(
        MeshPayloadMode::PreferV2,
        [0xAA; 32],
        book,
    );

    let sender = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let envelope = sample_envelope(sender, peer);
    transport.send(&peer, &envelope).await.unwrap();

    assert_eq!(
        protocol_store.lock().unwrap().as_deref(),
        Some(BITSOV_MESH_PROTOCOL_ID)
    );
    let bytes = payload_store.lock().unwrap().clone().unwrap();
    let decoded = decode_mesh_ukm(&bytes, &[0xBB; 32], None).unwrap();
    assert_eq!(decoded.id, envelope.id);
}

#[tokio::test]
async fn hybrid_v2_uses_encrypted_protocol_with_peer_x25519() {
    let alice_secret = StaticSecret::from([0x01; 32]);
    let bob_secret = StaticSecret::from([0x02; 32]);
    let alice_sk = alice_secret.to_bytes();
    let bob_sk = bob_secret.to_bytes();
    let bob_pk = *PublicKey::from(&bob_secret).as_bytes();

    let payload_store = Arc::new(Mutex::new(None));
    let protocol_store = Arc::new(Mutex::new(None));
    let mesh = Arc::new(RecordingMesh {
        last_payload: payload_store.clone(),
        last_protocol: protocol_store.clone(),
    });

    let mut reg = PeerRegistry::new();
    let bob = NodeId::from_bytes([2; 32]);
    reg.add(PeerEntry {
        node_id: bob,
        addr: SocketAddr::from(([127, 0, 0, 1], 9735)),
        label: None,
        auto_connect: false,
    });
    let mut bindings = std::collections::HashMap::new();
    bindings.insert(
        bob,
        konsensus_blvm_transport::MeshPeerBinding {
            mesh_node_id: None,
            peer_x25519: Some(bob_pk),
        },
    );
    let book: Arc<dyn MeshAddressBook> = Arc::new(RegistryMeshAddressBook::with_bindings(
        Arc::new(RwLock::new(reg)),
        NodeId::from_bytes([1; 32]),
        bindings,
    ));

    let transport = HybridBlvmTransport::new(Arc::new(OfflineDirect), mesh).with_mesh_encoding(
        MeshPayloadMode::V2,
        alice_sk,
        book,
    );

    let sender = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let envelope = sample_envelope(sender, peer);
    transport.send(&peer, &envelope).await.unwrap();

    assert_eq!(
        protocol_store.lock().unwrap().as_deref(),
        Some(BITSOV_MESH_PROTOCOL_ID_V2)
    );
    let bytes = payload_store.lock().unwrap().clone().unwrap();
    let alice_pk = *PublicKey::from(&alice_secret).as_bytes();
    let decoded = decode_mesh_ukm(&bytes, &bob_sk, Some(alice_pk)).unwrap();
    assert_eq!(decoded.id, envelope.id);
}

#[tokio::test]
async fn mesh_sender_fallback_resolves_distinct_mesh_destination() {
    let recorder = Arc::new(RecordingSender {
        last_dest: Mutex::new(None),
    });
    let book = address_book_with_peer(2, Some(0xDD), None, 1);
    let mesh = MeshSenderFallback::with_address_book(recorder.clone(), book);

    let bitsov_peer = NodeId::from_bytes([2; 32]);
    mesh.send_via_mesh(&bitsov_peer, b"payload", BITSOV_MESH_PROTOCOL_ID, None)
        .await
        .unwrap();

    assert_eq!(*recorder.last_dest.lock().unwrap(), Some([0xDD; 32]));
}

#[tokio::test]
async fn mesh_v2_end_to_end_encode_decode_with_address_book_keys() {
    let alice_secret = StaticSecret::from([0x10; 32]);
    let bob_secret = StaticSecret::from([0x20; 32]);
    let alice_sk = alice_secret.to_bytes();
    let bob_sk = bob_secret.to_bytes();
    let alice_pk = *PublicKey::from(&alice_secret).as_bytes();
    let bob_pk = *PublicKey::from(&bob_secret).as_bytes();

    let alice = NodeId::from_bytes([0xA1; 32]);
    let bob = NodeId::from_bytes([0xB2; 32]);
    let envelope = sample_envelope(alice, bob);

    let (bytes, proto) =
        encode_ukm_for_mesh(&envelope, MeshPayloadMode::V2, &alice_sk, Some(bob_pk)).unwrap();
    assert_eq!(proto, BITSOV_MESH_PROTOCOL_ID_V2);

    let decoded = decode_mesh_ukm(&bytes, &bob_sk, Some(alice_pk)).unwrap();
    assert_eq!(decoded.sender, alice);
    assert_eq!(decoded.id, envelope.id);
}
