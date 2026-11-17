//! Unit tests for mesh hop payment acquisition.

use std::sync::Arc;

use async_trait::async_trait;
use konsensus_blvm_payment::{
    resolve_mesh_route_payment, LightningMeshHopAcquirer, MeshHopError, MeshHopPaymentAcquirer,
    MeshHopPolicy, MeshRoutePayment,
};
use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::types::PaymentProof;
use konsensus_lightning::MockLightningProvider;

const DEST: [u8; 32] = [0xDE; 32];

struct FixedAcquirer;

#[async_trait]
impl MeshHopPaymentAcquirer for FixedAcquirer {
    async fn acquire_hop_payment(
        &self,
        destination: [u8; 32],
        amount_msat: u64,
    ) -> Result<MeshRoutePayment, MeshHopError> {
        assert_eq!(destination, DEST);
        Ok(MeshRoutePayment::Lightning {
            invoice: "lnbc1mock".into(),
            preimage: [0xAB; 32],
            amount_msats: amount_msat,
            timestamp: 1,
            expires_at: 9999,
        })
    }
}

#[tokio::test]
async fn lightning_acquirer_creates_and_pays_invoice() {
    let ln = Arc::new(MockLightningProvider::new());
    let acquirer = LightningMeshHopAcquirer::new(ln);
    let proof = acquirer.acquire_hop_payment(DEST, 1000).await.unwrap();
    match proof {
        MeshRoutePayment::Lightning {
            invoice,
            preimage,
            amount_msats,
            ..
        } => {
            assert!(!invoice.is_empty());
            assert_ne!(preimage, [0u8; 32]);
            assert_eq!(amount_msats, 1000);
        }
        _ => panic!("expected lightning proof"),
    }
}

#[test]
fn resolve_uses_gate_proof_when_blvm_on_chain() {
    let gate = GatePaymentProof::BlvmOnChainSession {
        payment_request_id: "req".into(),
        tx_hash: [1u8; 32],
        amount_sats: 100,
        timestamp: 1,
        session_debit_seq: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolved = rt
        .block_on(resolve_mesh_route_payment(
            &gate,
            DEST,
            1000,
            true,
            MeshHopPolicy::Disabled,
            None,
        ))
        .unwrap();
    assert!(matches!(
        resolved,
        Some(MeshRoutePayment::OnChainSettlement { .. })
    ));
}

#[tokio::test]
async fn resolve_acquires_hop_for_lightning_when_per_send() {
    let gate = GatePaymentProof::Lightning(PaymentProof::new([1u8; 32], [2u8; 32], 500));
    let resolved = resolve_mesh_route_payment(
        &gate,
        DEST,
        1000,
        true,
        MeshHopPolicy::PerSend,
        Some(&FixedAcquirer),
    )
    .await
    .unwrap()
    .expect("hop proof");
    assert!(matches!(resolved, MeshRoutePayment::Lightning { .. }));
}

#[tokio::test]
async fn resolve_fail_closed_when_required_no_acquirer() {
    let gate = GatePaymentProof::Lightning(PaymentProof::new([1u8; 32], [2u8; 32], 500));
    let err = resolve_mesh_route_payment(&gate, DEST, 1000, true, MeshHopPolicy::Disabled, None)
        .await
        .unwrap_err();
    assert!(matches!(err, MeshHopError::AcquirerMissing));
}

#[tokio::test]
async fn resolve_none_when_open_relay_and_disabled_policy() {
    let gate = GatePaymentProof::Lightning(PaymentProof::new([1u8; 32], [2u8; 32], 500));
    let resolved =
        resolve_mesh_route_payment(&gate, DEST, 1000, false, MeshHopPolicy::Disabled, None)
            .await
            .unwrap();
    assert!(resolved.is_none());
}

#[test]
fn mesh_hop_policy_from_config_str() {
    use konsensus_blvm_payment::MeshHopPolicy;
    assert_eq!(
        MeshHopPolicy::from_config_str("disabled"),
        Some(MeshHopPolicy::Disabled)
    );
    assert_eq!(
        MeshHopPolicy::from_config_str("per_send"),
        Some(MeshHopPolicy::PerSend)
    );
    assert!(MeshHopPolicy::from_config_str("invalid").is_none());
}

#[test]
fn mesh_hop_invoice_source_from_config_str() {
    use konsensus_blvm_payment::MeshHopInvoiceSource;
    assert_eq!(
        MeshHopInvoiceSource::from_config_str("self"),
        Some(MeshHopInvoiceSource::SelfIssue)
    );
    assert_eq!(
        MeshHopInvoiceSource::from_config_str("relay"),
        Some(MeshHopInvoiceSource::Relay)
    );
    assert!(MeshHopInvoiceSource::from_config_str("invalid").is_none());
}

#[tokio::test]
async fn per_send_acquires_hop_even_when_payment_not_required() {
    let gate = GatePaymentProof::Lightning(PaymentProof::new([1u8; 32], [2u8; 32], 500));
    let resolved = resolve_mesh_route_payment(
        &gate,
        DEST,
        1000,
        false,
        MeshHopPolicy::PerSend,
        Some(&FixedAcquirer),
    )
    .await
    .unwrap()
    .expect("hop proof");
    assert!(matches!(resolved, MeshRoutePayment::Lightning { .. }));
}

#[tokio::test]
async fn lightning_acquirer_returns_nonzero_preimage() {
    let ln = Arc::new(MockLightningProvider::new());
    let acquirer = LightningMeshHopAcquirer::new(ln);
    let proof = acquirer.acquire_hop_payment(DEST, 1000).await.unwrap();
    let MeshRoutePayment::Lightning {
        invoice,
        preimage,
        amount_msats,
        ..
    } = proof
    else {
        panic!("expected lightning");
    };
    assert_ne!(preimage, [0u8; 32]);
    assert!(!invoice.is_empty());
    assert_eq!(amount_msats, 1000);
}
