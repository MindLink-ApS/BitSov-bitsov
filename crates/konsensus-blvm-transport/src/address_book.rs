//! Resolve BitSov peer ids ↔ blvm-mesh destination ids.
//!
//! Mesh ids and X25519 keys live beside the peer registry. `PeerEntry` stays the
//! Lightning address book: existing configs do not grow mesh fields.

use std::collections::HashMap;
use std::sync::RwLock as StdRwLock;

use async_trait::async_trait;
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;
use konsensus_message::peer::PeerRegistry;
use tokio::sync::RwLock;

/// Lookup mesh routing ids and peer X25519 keys for hybrid transport.
#[async_trait]
pub trait MeshAddressBook: Send + Sync {
    async fn resolve_mesh_destination(
        &self,
        bitsov_peer: &NodeId,
    ) -> Result<[u8; 32], TransportError>;
    async fn resolve_bitsov_sender(&self, mesh_source: &[u8; 32])
        -> Result<NodeId, TransportError>;
    async fn peer_x25519(&self, bitsov_peer: &NodeId) -> Option<[u8; 32]>;
}

/// Optional mesh identity for one BitSov peer.
#[derive(Debug, Clone, Default)]
pub struct MeshPeerBinding {
    pub mesh_node_id: Option<NodeId>,
    pub peer_x25519: Option<[u8; 32]>,
}

/// Address book backed by the node peer registry plus mesh bindings.
pub struct RegistryMeshAddressBook {
    registry: std::sync::Arc<RwLock<PeerRegistry>>,
    local_mesh_id: NodeId,
    bindings: StdRwLock<HashMap<NodeId, MeshPeerBinding>>,
}

impl RegistryMeshAddressBook {
    pub fn new(registry: std::sync::Arc<RwLock<PeerRegistry>>, local_mesh_id: NodeId) -> Self {
        Self::with_bindings(registry, local_mesh_id, HashMap::new())
    }

    pub fn with_bindings(
        registry: std::sync::Arc<RwLock<PeerRegistry>>,
        local_mesh_id: NodeId,
        bindings: HashMap<NodeId, MeshPeerBinding>,
    ) -> Self {
        Self {
            registry,
            local_mesh_id,
            bindings: StdRwLock::new(bindings),
        }
    }
}

#[async_trait]
impl MeshAddressBook for RegistryMeshAddressBook {
    async fn resolve_mesh_destination(
        &self,
        bitsov_peer: &NodeId,
    ) -> Result<[u8; 32], TransportError> {
        if let Some(mesh_id) = self
            .bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(bitsov_peer)
            .and_then(|b| b.mesh_node_id)
        {
            return Ok(*mesh_id.as_bytes());
        }
        let registry = self.registry.read().await;
        if registry.contains(bitsov_peer) {
            return Ok(*bitsov_peer.as_bytes());
        }
        Err(TransportError::Other(format!(
            "no mesh destination binding for peer {}",
            bitsov_peer.to_hex()
        )))
    }

    async fn resolve_bitsov_sender(
        &self,
        mesh_source: &[u8; 32],
    ) -> Result<NodeId, TransportError> {
        let mesh_id = NodeId::from_bytes(*mesh_source);
        if let Some((bitsov, _)) = self
            .bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(_, binding)| binding.mesh_node_id == Some(mesh_id))
        {
            return Ok(*bitsov);
        }
        let registry = self.registry.read().await;
        for entry in registry.all() {
            if entry.node_id == mesh_id {
                return Ok(entry.node_id);
            }
        }
        if mesh_id == self.local_mesh_id {
            return Ok(self.local_mesh_id);
        }
        Err(TransportError::Other(format!(
            "unbound mesh source {}",
            mesh_id.to_hex()
        )))
    }

    async fn peer_x25519(&self, bitsov_peer: &NodeId) -> Option<[u8; 32]> {
        self.bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(bitsov_peer)
            .and_then(|b| b.peer_x25519)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_message::peer::{PeerEntry, PeerRegistry};
    use std::net::SocketAddr;

    fn peer(id_byte: u8) -> PeerEntry {
        PeerEntry {
            node_id: NodeId::from_bytes([id_byte; 32]),
            addr: SocketAddr::from(([127, 0, 0, 1], 9000 + id_byte as u16)),
            label: None,
            auto_connect: false,
        }
    }

    fn book(
        entries: Vec<PeerEntry>,
        bindings: HashMap<NodeId, MeshPeerBinding>,
        local: u8,
    ) -> RegistryMeshAddressBook {
        let mut reg = PeerRegistry::new();
        for e in entries {
            reg.add(e);
        }
        RegistryMeshAddressBook::with_bindings(
            std::sync::Arc::new(RwLock::new(reg)),
            NodeId::from_bytes([local; 32]),
            bindings,
        )
    }

    #[tokio::test]
    async fn resolve_mesh_destination_uses_explicit_mesh_id() {
        let bitsov = NodeId::from_bytes([1; 32]);
        let mut bindings = HashMap::new();
        bindings.insert(
            bitsov,
            MeshPeerBinding {
                mesh_node_id: Some(NodeId::from_bytes([0xAA; 32])),
                peer_x25519: None,
            },
        );
        let book = book(vec![peer(1)], bindings, 2);
        let dest = book.resolve_mesh_destination(&bitsov).await.unwrap();
        assert_eq!(dest, [0xAA; 32]);
    }

    #[tokio::test]
    async fn resolve_mesh_destination_falls_back_to_bitsov_id() {
        let book = book(vec![peer(1)], HashMap::new(), 2);
        let bitsov = NodeId::from_bytes([1; 32]);
        let dest = book.resolve_mesh_destination(&bitsov).await.unwrap();
        assert_eq!(dest, [1; 32]);
    }

    #[tokio::test]
    async fn resolve_mesh_destination_unknown_peer_fails() {
        let book = book(vec![], HashMap::new(), 2);
        let unknown = NodeId::from_bytes([9; 32]);
        assert!(book.resolve_mesh_destination(&unknown).await.is_err());
    }

    #[tokio::test]
    async fn resolve_bitsov_sender_via_mesh_id_mapping() {
        let bitsov = NodeId::from_bytes([1; 32]);
        let mut bindings = HashMap::new();
        bindings.insert(
            bitsov,
            MeshPeerBinding {
                mesh_node_id: Some(NodeId::from_bytes([0xBB; 32])),
                peer_x25519: None,
            },
        );
        let book = book(vec![peer(1)], bindings, 2);
        let found = book.resolve_bitsov_sender(&[0xBB; 32]).await.unwrap();
        assert_eq!(found, bitsov);
    }

    #[tokio::test]
    async fn resolve_bitsov_sender_unified_id() {
        let book = book(vec![peer(1)], HashMap::new(), 2);
        let bitsov = book.resolve_bitsov_sender(&[1; 32]).await.unwrap();
        assert_eq!(bitsov, NodeId::from_bytes([1; 32]));
    }

    #[tokio::test]
    async fn resolve_bitsov_sender_local_node() {
        let book = book(vec![], HashMap::new(), 0xCC);
        let bitsov = book.resolve_bitsov_sender(&[0xCC; 32]).await.unwrap();
        assert_eq!(bitsov, NodeId::from_bytes([0xCC; 32]));
    }

    #[tokio::test]
    async fn resolve_bitsov_sender_unbound_fails() {
        let book = book(vec![], HashMap::new(), 2);
        assert!(book.resolve_bitsov_sender(&[0xDE; 32]).await.is_err());
    }

    #[tokio::test]
    async fn peer_x25519_lookup() {
        let bitsov = NodeId::from_bytes([1; 32]);
        let mut bindings = HashMap::new();
        bindings.insert(
            bitsov,
            MeshPeerBinding {
                mesh_node_id: None,
                peer_x25519: Some([0x55; 32]),
            },
        );
        let book = book(vec![peer(1)], bindings, 2);
        assert_eq!(book.peer_x25519(&bitsov).await, Some([0x55; 32]));
        assert!(book
            .peer_x25519(&NodeId::from_bytes([9; 32]))
            .await
            .is_none());
    }
}
