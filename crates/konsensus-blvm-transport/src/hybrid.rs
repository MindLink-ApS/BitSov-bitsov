//! Hybrid transport selector (D-2): direct Noise preferred, mesh fallback.

use std::sync::Arc;

use async_trait::async_trait;
use konsensus_blvm_payment::{
    gate_proof_to_mesh_payment_ctv, resolve_mesh_route_payment, MeshHopPaymentAcquirer,
    MeshHopPolicy, MeshRoutePayment,
};
use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::traits::transport::{ConnectedPeerInfo, MessageTransport, TransportError};
use konsensus_core::types::NodeId;
use tracing::debug;

use crate::address_book::MeshAddressBook;
use crate::mesh_payload::{encode_mesh_control_frame, encode_ukm_for_mesh, MeshPayloadMode};

/// Private protocol id for UKM payloads on blvm-mesh (opaque to the mesh layer).
pub const BITSOV_MESH_PROTOCOL_ID: &str = "bitsov-ukm-v1";

/// Mesh send path used when direct Noise is unavailable.
#[async_trait]
pub trait MeshFallback: Send + Sync {
    async fn send_via_mesh(
        &self,
        destination: &NodeId,
        payload: &[u8],
        protocol_id: &str,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError>;
}

/// Per-send mesh hop payment configuration (Phase C).
#[derive(Clone)]
pub struct MeshHopSendConfig {
    pub payment_required: bool,
    pub hop_msat: u64,
    pub control_hop_msat: u64,
    pub hop_policy: MeshHopPolicy,
    pub acquirer: Arc<dyn MeshHopPaymentAcquirer>,
}

/// Tries `direct` when connected; otherwise serializes the UKM and sends via mesh.
pub struct HybridBlvmTransport<D, M> {
    direct: Arc<D>,
    mesh: Arc<M>,
    payload_mode: MeshPayloadMode,
    local_x25519: [u8; 32],
    address_book: Option<Arc<dyn MeshAddressBook>>,
    mesh_hop: Option<MeshHopSendConfig>,
    /// Path 2 hop payment (`InstantSettlement`) is sent only when this is set.
    mesh_ctv: bool,
}

impl<D, M> HybridBlvmTransport<D, M> {
    pub fn new(direct: Arc<D>, mesh: Arc<M>) -> Self {
        Self {
            direct,
            mesh,
            payload_mode: MeshPayloadMode::V1,
            local_x25519: [0u8; 32],
            address_book: None,
            mesh_hop: None,
            mesh_ctv: false,
        }
    }

    pub fn with_mesh_ctv(mut self, mesh_ctv: bool) -> Self {
        self.mesh_ctv = mesh_ctv;
        self
    }

    pub fn with_mesh_encoding(
        mut self,
        mode: MeshPayloadMode,
        local_x25519: [u8; 32],
        address_book: Arc<dyn MeshAddressBook>,
    ) -> Self {
        self.payload_mode = mode;
        self.local_x25519 = local_x25519;
        self.address_book = Some(address_book);
        self
    }

    pub fn with_mesh_hop(mut self, config: MeshHopSendConfig) -> Self {
        self.mesh_hop = Some(config);
        self
    }

    async fn resolve_mesh_destination(&self, peer: &NodeId) -> Result<[u8; 32], TransportError> {
        if let Some(book) = &self.address_book {
            book.resolve_mesh_destination(peer).await
        } else {
            Ok(*peer.as_bytes())
        }
    }

    async fn resolve_hop_payment_for_ukm(
        &self,
        peer: &NodeId,
        envelope: &UkmEnvelope,
    ) -> Result<Option<MeshRoutePayment>, TransportError> {
        let route_from_gate =
            gate_proof_to_mesh_payment_ctv(&envelope.payment_proof, self.mesh_ctv)
                .map_err(|e| TransportError::Other(e.to_string()))?;
        if route_from_gate.is_some() {
            return Ok(route_from_gate);
        }

        let Some(hop) = &self.mesh_hop else {
            return Ok(None);
        };

        let mesh_dest = self.resolve_mesh_destination(peer).await?;
        resolve_mesh_route_payment(
            &envelope.payment_proof,
            mesh_dest,
            hop.hop_msat,
            hop.payment_required,
            hop.hop_policy,
            Some(hop.acquirer.as_ref()),
        )
        .await
        .map_err(|e| TransportError::Other(e.to_string()))
    }

    async fn resolve_hop_payment_for_control(
        &self,
        peer: &NodeId,
    ) -> Result<Option<MeshRoutePayment>, TransportError> {
        let Some(hop) = &self.mesh_hop else {
            return Ok(None);
        };

        if !hop.payment_required && hop.hop_policy == MeshHopPolicy::Disabled {
            return Ok(None);
        }

        match hop.hop_policy {
            MeshHopPolicy::Disabled if hop.payment_required => Err(TransportError::Other(
                "mesh hop payment required for control frame but hop policy is disabled".into(),
            )),
            MeshHopPolicy::Disabled => Ok(None),
            MeshHopPolicy::PerSend => {
                let mesh_dest = self.resolve_mesh_destination(peer).await?;
                hop.acquirer
                    .acquire_hop_payment(mesh_dest, hop.control_hop_msat)
                    .await
                    .map(Some)
                    .map_err(|e| TransportError::Other(e.to_string()))
            }
        }
    }
}

#[async_trait]
impl<D: MessageTransport, M: MeshFallback> MessageTransport for HybridBlvmTransport<D, M> {
    async fn send(&self, peer: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if self.direct.is_connected(peer).await {
            debug!(peer = %peer.to_hex(), "hybrid transport: direct send");
            return self.direct.send(peer, envelope).await;
        }

        debug!(peer = %peer.to_hex(), "hybrid transport: mesh fallback");
        let peer_x25519 = if let Some(book) = &self.address_book {
            book.peer_x25519(peer).await
        } else {
            None
        };
        let (payload, protocol_id) =
            encode_ukm_for_mesh(envelope, self.payload_mode, &self.local_x25519, peer_x25519)?;
        let route_payment = self.resolve_hop_payment_for_ukm(peer, envelope).await?;
        self.mesh
            .send_via_mesh(peer, &payload, protocol_id, route_payment)
            .await
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        self.direct.recv().await
    }

    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), TransportError> {
        self.direct.connect(peer, addr).await
    }

    async fn disconnect(&self, peer: &NodeId) -> Result<(), TransportError> {
        self.direct.disconnect(peer).await
    }

    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.direct.is_connected(peer).await
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        self.direct.connected_peers().await
    }

    async fn request_peer_exchange(&self, peer: &NodeId) -> Result<(), TransportError> {
        self.direct.request_peer_exchange(peer).await
    }

    async fn send_raw_frame(
        &self,
        peer: &NodeId,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        if self.direct.is_connected(peer).await {
            return self.direct.send_raw_frame(peer, frame_bytes).await;
        }

        debug!(peer = %peer.to_hex(), "hybrid transport: mesh fallback for control frame");
        let payload = encode_mesh_control_frame(frame_bytes);
        let route_payment = self.resolve_hop_payment_for_control(peer).await?;
        self.mesh
            .send_via_mesh(peer, &payload, BITSOV_MESH_PROTOCOL_ID, route_payment)
            .await
    }

    async fn peer_info(&self, peer: &NodeId) -> Option<ConnectedPeerInfo> {
        self.direct.peer_info(peer).await
    }

    async fn add_to_whitelist(&self, peer: &NodeId) {
        self.direct.add_to_whitelist(peer).await
    }

    async fn remove_from_whitelist(&self, peer: &NodeId) {
        self.direct.remove_from_whitelist(peer).await
    }

    async fn supervise_peer(&self, peer: &NodeId, addr: &str) {
        self.direct.supervise_peer(peer, addr).await
    }
}
