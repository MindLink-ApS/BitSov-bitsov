//! BLVM payment integration for BitSov UKM gate paths 2–3.

mod covenant_merkle;
mod mesh_hop;
mod mesh_proof;
mod mesh_route;
mod mesh_rpc;
mod mesh_smoke;
mod rpc;
mod rpc_http;
mod verifier;

mod session_manager;
mod session_store;

pub mod providers;

pub use mesh_hop::{
    resolve_mesh_route_payment, LightningMeshHopAcquirer, MeshHopError, MeshHopInvoiceSource,
    MeshHopPaymentAcquirer, MeshHopPolicy, RelayMeshHopAcquirer,
};

pub use mesh_proof::{gate_proof_to_mesh_payment, gate_proof_to_mesh_payment_ctv};
pub use mesh_route::{MeshPaymentProof, MeshRoutePayment};
pub use mesh_rpc::{
    HttpBlvmMeshRpc, MeshHopInvoiceResponse, MeshPolledPacket, MeshSendPacketRequest,
    MeshSendPacketResponse,
};
pub use mesh_smoke::mesh_send_request_hex;
pub use providers::covenant::{BlvmCovenantPaymentProvider, CovenantPaymentResult};
pub use rpc::{
    BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification, PaymentRequestOutput,
    PaymentStateSnapshot, RpcBlvmError,
};
pub use rpc_http::HttpBlvmNodeRpc;
pub use session_manager::{BlvmOnChainSessionManager, SessionManagerError};
pub use session_store::{
    mem_try_debit_record, OnChainSessionDebit, OnChainSessionRecord, OnChainSessionStore,
    SessionStoreError,
};
pub use verifier::{probe_payment_module, BlvmGateVerifier};
