//! Mesh packet sender trait — implemented by node layer with `blvm_mesh::MeshClient`.

use async_trait::async_trait;
use konsensus_blvm_payment::MeshRoutePayment;
use konsensus_core::traits::transport::TransportError;

/// Sends opaque payloads through blvm-mesh (node adapter implements via `MeshClient`).
#[async_trait]
pub trait MeshPacketSender: Send + Sync {
    async fn send_mesh_packet(
        &self,
        destination: [u8; 32],
        payload: Vec<u8>,
        protocol_id: String,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError>;
}
