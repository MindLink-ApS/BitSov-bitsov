//! Circular HTLCs must not alter the independent outbound payment.
use super::*;

#[tokio::test]
async fn circular_receive_preserves_pending_and_succeeded_outbound_records() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let mut receipts = Vec::new();
    for (index, status) in [PaymentStatus::Pending, PaymentStatus::Succeeded]
        .into_iter()
        .enumerate()
    {
        let preimage = PaymentPreimage([70 + index as u8; 32]);
        let hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
        let id = PaymentId(hash.0);
        let mut receipt = PaymentDetails::new(
            id,
            PaymentKind::Bolt11 {
                hash,
                preimage: Some(preimage),
                secret: Some(PaymentSecret([72; 32])),
            },
            Some(10_000),
            Some(42),
            PaymentDirection::Outbound,
            status,
        );
        receipt.latest_update_timestamp = 1_700_000_000;
        node.payment_store.insert(receipt.clone()).unwrap();
        log.0.lock().unwrap().clear();
        handler(&node)
            .handle_event(claimable(
                hash,
                PaymentPurpose::SpontaneousPayment(preimage),
                10_000,
                0,
            ))
            .await
            .unwrap();
        assert_eq!(
            node.payment(&id).unwrap(),
            receipt,
            "inbound HTLC altered outbound record"
        );
        assert!(
            !reached_claim(&log),
            "circular HTLC must not release the preimage"
        );
        assert!(node.next_event().is_none());
        receipts.push(receipt);
    }
    drop(node);
    let node = builder.build_with_fs_store().unwrap();
    for receipt in receipts {
        assert_eq!(node.payment(&receipt.id).unwrap(), receipt);
    }
    assert!(node.next_event().is_none());
}
