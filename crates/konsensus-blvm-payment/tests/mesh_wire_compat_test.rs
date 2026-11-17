//! Bincode wire compatibility with blvm-mesh `PaymentProof`.

use konsensus_blvm_payment::{
    gate_proof_to_mesh_payment, gate_proof_to_mesh_payment_ctv, MeshPaymentProof,
};
use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::types::PaymentProof;

#[test]
fn on_chain_settlement_variant_index_matches_blvm_mesh() {
    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-1".into(),
        tx_hash: [0x11; 32],
        amount_sats: 50_000,
        timestamp: 1_700_000_000,
        session_debit_seq: Some(1),
    };
    let mesh = gate_proof_to_mesh_payment(&proof).unwrap().unwrap();
    let bytes = bincode::serialize(&mesh).unwrap();
    // blvm-mesh PaymentProof variant 1 (OnChainSettlement) starts with index 1
    assert_eq!(bytes[0], 1, "OnChainSettlement must be bincode variant 1");
}

#[test]
fn instant_settlement_variant_index_matches_blvm_mesh() {
    let proof = GatePaymentProof::BlvmCovenant {
        covenant_proof: vec![0xab; 64],
        output_index: 0,
        amount_sats: 10_000,
        timestamp: 2,
    };
    let mesh = gate_proof_to_mesh_payment_ctv(&proof, true).unwrap().unwrap();
    let bytes = bincode::serialize(&mesh).unwrap();
    assert_eq!(bytes[0], 2, "InstantSettlement must be bincode variant 2");
    assert!(gate_proof_to_mesh_payment(&proof).is_err());

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    enum DefaultMeshPaymentProof {
        Lightning {
            invoice: String,
            preimage: [u8; 32],
            amount_msats: u64,
            timestamp: u64,
            expires_at: u64,
        },
        OnChainSettlement {
            payment_request_id: String,
            tx_hash: [u8; 32],
            amount_sats: u64,
            timestamp: u64,
        },
    }
    assert!(bincode::deserialize::<DefaultMeshPaymentProof>(&bytes).is_err());
}

#[test]
fn lightning_variant_layout_for_future_path1_mesh_hop() {
    let mesh = MeshPaymentProof::Lightning {
        invoice: "lnbc1test".into(),
        preimage: [0x42; 32],
        amount_msats: 25_000,
        timestamp: 100,
        expires_at: 200,
    };
    let bytes = bincode::serialize(&mesh).unwrap();
    assert_eq!(bytes[0], 0, "Lightning must be bincode variant 0");
}

#[test]
fn legacy_lightning_gate_proof_still_maps_to_none_for_mesh_route() {
    let ln = PaymentProof::new([1; 32], [2; 32], 999);
    let gate = GatePaymentProof::Lightning(ln);
    assert!(gate_proof_to_mesh_payment(&gate).unwrap().is_none());
}
