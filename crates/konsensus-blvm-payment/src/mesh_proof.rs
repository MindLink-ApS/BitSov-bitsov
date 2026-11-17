//! Map UKM gate proofs to mesh route payment DTOs.

use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::traits::blvm_payment::BlvmPaymentError;

use crate::covenant_merkle::merkle_proof_from_covenant;
use crate::mesh_route::MeshRoutePayment;

/// Convert a UKM gate proof to a mesh hop payment proof when applicable.
///
/// Lightning UKM proofs (path 1) do not embed BOLT11 and cannot be used for mesh
/// routing payment — callers must supply a separate mesh route payment.
///
/// Path 2 (`InstantSettlement`, bincode variant 2) is refused unless `mesh_ctv`
/// is set. A default blvm-mesh build at `070645f` does not include that variant.
pub fn gate_proof_to_mesh_payment(
    proof: &GatePaymentProof,
) -> Result<Option<MeshRoutePayment>, BlvmPaymentError> {
    gate_proof_to_mesh_payment_ctv(proof, false)
}

pub fn gate_proof_to_mesh_payment_ctv(
    proof: &GatePaymentProof,
    mesh_ctv: bool,
) -> Result<Option<MeshRoutePayment>, BlvmPaymentError> {
    match proof {
        GatePaymentProof::Lightning(_) => Ok(None),
        GatePaymentProof::BlvmOnChainSession {
            payment_request_id,
            tx_hash,
            amount_sats,
            timestamp,
            ..
        } => Ok(Some(MeshRoutePayment::OnChainSettlement {
            payment_request_id: payment_request_id.clone(),
            tx_hash: *tx_hash,
            amount_sats: *amount_sats,
            timestamp: *timestamp,
        })),
        GatePaymentProof::BlvmCovenant {
            covenant_proof,
            output_index,
            amount_sats,
            timestamp,
        } => {
            if !mesh_ctv {
                return Err(BlvmPaymentError::CovenantRejected(
                    "path 2 mesh requires mesh_ctv; default blvm-mesh has no InstantSettlement"
                        .into(),
                ));
            }
            Ok(Some(MeshRoutePayment::InstantSettlement {
                covenant_proof: covenant_proof.clone(),
                output_index: *output_index,
                merkle_proof: merkle_proof_from_covenant(covenant_proof),
                amount_sats: *amount_sats,
                timestamp: *timestamp,
            }))
        }
    }
}
