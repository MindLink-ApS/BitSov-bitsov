use konsensus_blvm_payment::{
    gate_proof_to_mesh_payment, gate_proof_to_mesh_payment_ctv, MeshRoutePayment,
};
use konsensus_core::gate_payment::GatePaymentProof;

#[test]
fn on_chain_gate_proof_maps_to_mesh_route_payment() {
    let proof = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req-99".into(),
        tx_hash: [0x55; 32],
        amount_sats: 50_000,
        timestamp: 123,
        session_debit_seq: Some(2),
    };

    let mesh = gate_proof_to_mesh_payment(&proof)
        .expect("conversion")
        .expect("some mesh proof");

    assert!(matches!(
        mesh,
        MeshRoutePayment::OnChainSettlement {
            payment_request_id,
            tx_hash,
            amount_sats,
            timestamp,
        } if payment_request_id == "req-99"
            && tx_hash == [0x55; 32]
            && amount_sats == 50_000
            && timestamp == 123
    ));
}

#[test]
fn covenant_gate_proof_maps_to_instant_settlement() {
    let template_hash = [0xAA; 32];
    let covenant_bytes = serde_json::to_vec(&serde_json::json!({
        "template_hash": template_hash,
        "payment_request_id": "req-cov",
        "created_at": 456,
    }))
    .unwrap();

    let proof = GatePaymentProof::BlvmCovenant {
        covenant_proof: covenant_bytes,
        output_index: 1,
        amount_sats: 10_000,
        timestamp: 456,
    };

    let mesh = gate_proof_to_mesh_payment_ctv(&proof, true)
        .expect("conversion")
        .expect("mesh proof");
    assert!(gate_proof_to_mesh_payment(&proof).is_err());

    assert!(matches!(
        mesh,
        MeshRoutePayment::InstantSettlement {
            output_index: 1,
            amount_sats: 10_000,
            timestamp: 456,
            merkle_proof,
            ..
        } if merkle_proof == vec![template_hash]
    ));
}

#[test]
fn lightning_gate_proof_has_no_mesh_route_payment() {
    use konsensus_core::types::PaymentProof;
    let proof = GatePaymentProof::Lightning(PaymentProof::new([1; 32], [2; 32], 1000));
    assert!(gate_proof_to_mesh_payment(&proof).unwrap().is_none());
}
