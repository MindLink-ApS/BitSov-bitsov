//! Wire-compatible mesh route payment DTO (matches blvm-mesh `PaymentProof` bincode layout).

use serde::{Deserialize, Serialize};

/// Mesh hop payment proof — bincode-compatible with blvm-mesh `PaymentProof`.
///
/// Variant order must match blvm-mesh exactly:
/// 0 Lightning → 1 OnChainSettlement → 2 InstantSettlement (ctv).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshPaymentProof {
    /// Lightning payment proof (BOLT11 invoice + preimage)
    Lightning {
        invoice: String,
        preimage: [u8; 32],
        amount_msats: u64,
        timestamp: u64,
        expires_at: u64,
    },
    /// On-chain settlement proof (BIP70 session / mempool attestation, path 3)
    OnChainSettlement {
        payment_request_id: String,
        tx_hash: [u8; 32],
        amount_sats: u64,
        timestamp: u64,
    },
    /// CTV instant settlement proof (path 2)
    InstantSettlement {
        covenant_proof: Vec<u8>,
        output_index: u32,
        merkle_proof: Vec<[u8; 32]>,
        amount_sats: u64,
        timestamp: u64,
    },
}

impl MeshPaymentProof {
    pub fn to_bincode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }
}

/// Backward-compatible alias during migration.
pub type MeshRoutePayment = MeshPaymentProof;
