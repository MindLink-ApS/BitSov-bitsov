//! Hybrid BitSov transport: direct Noise (`MessageTransport`) with mesh fallback.
//!
//! Wire mesh at node bootstrap by implementing [`MeshPacketSender`] with
//! `blvm_mesh::MeshClient::send_packet` (map [`konsensus_blvm_payment::MeshRoutePayment`]
//! to `blvm_mesh::payment_proof::PaymentProof`), then pass [`MeshSenderFallback`] to
//! [`HybridBlvmTransport`].

mod address_book;
mod hybrid;
mod mesh_adapter;
mod mesh_carriage;
mod mesh_payload;
mod mesh_sender;

pub use address_book::{MeshAddressBook, MeshPeerBinding, RegistryMeshAddressBook};
pub use hybrid::{HybridBlvmTransport, MeshFallback, MeshHopSendConfig, BITSOV_MESH_PROTOCOL_ID};
pub use mesh_adapter::MeshSenderFallback;
pub use mesh_payload::{
    decode_mesh_ukm, decode_ukm, encode_mesh_control_frame, encode_ukm, encode_ukm_for_mesh,
    try_decode_mesh_control_frame, MeshPayloadMode, BITSOV_MESH_PROTOCOL_ID_V2,
    MAX_MESH_CONTROL_FRAME_BYTES, MAX_MESH_UKM_BYTES, MESH_CONTROL_MAGIC, MESH_UKM_V2_MAGIC,
};
pub use mesh_sender::MeshPacketSender;
