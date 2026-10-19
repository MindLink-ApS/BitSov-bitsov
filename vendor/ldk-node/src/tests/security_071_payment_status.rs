//! Real handler/store regressions; no funded node or network is required.
use super::*;

fn lightning_kinds(hash: PaymentHash) -> Vec<PaymentKind> {
    vec![
        PaymentKind::Bolt11 {
            hash,
            preimage: None,
            secret: Some(PaymentSecret([41; 32])),
        },
        PaymentKind::Bolt11Jit {
            hash,
            preimage: None,
            secret: Some(PaymentSecret([42; 32])),
            counterparty_skimmed_fee_msat: Some(0),
            lsp_fee_limits: crate::payment::LSPFeeLimits {
                max_total_opening_fee_msat: Some(500),
                max_proportional_opening_fee_ppm_msat: None,
            },
        },
        PaymentKind::Bolt12Offer {
            hash: Some(hash),
            preimage: None,
            secret: None,
            offer_id: OfferId([43; 32]),
            payer_note: None,
            quantity: Some(2),
        },
        PaymentKind::Bolt12Refund {
            hash: Some(hash),
            preimage: None,
            secret: None,
            payer_note: None,
            quantity: Some(3),
        },
        PaymentKind::Spontaneous {
            hash,
            preimage: None,
        },
    ]
}

fn failed(id: PaymentId, hash: Option<PaymentHash>) -> LdkEvent {
    LdkEvent::PaymentFailed {
        payment_id: id,
        payment_hash: hash,
        reason: None,
    }
}

#[tokio::test]
async fn late_failure_preserves_successful_lightning_receipt_and_emits_no_failure() {
    let (_dir, builder, _log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let preimage = PaymentPreimage([44; 32]);
    let hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
    let mut receipts = Vec::new();
    for (index, kind) in lightning_kinds(hash).into_iter().enumerate() {
        // Deliberately not the hash: BOLT12/keysend IDs need not equal hashes.
        let id = PaymentId([50 + index as u8; 32]);
        node.payment_store
            .insert(PaymentDetails::new(
                id,
                kind,
                Some(10_000),
                None,
                PaymentDirection::Outbound,
                PaymentStatus::Pending,
            ))
            .unwrap();
        handler(&node)
            .handle_event(LdkEvent::PaymentSent {
                payment_id: Some(id),
                payment_preimage: preimage,
                payment_hash: hash,
                fee_paid_msat: Some(42),
                amount_msat: Some(10_000),
                bolt12_invoice: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            node.next_event(),
            Some(Event::PaymentSuccessful { .. })
        ));
        node.event_queue.event_handled().await.unwrap();
        let receipt = node.payment(&id).unwrap();
        assert_eq!(receipt.status, PaymentStatus::Succeeded);
        // A late event must not erase or replace the hash, fee, preimage or timestamp.
        for failure_hash in [Some(hash), None, Some(PaymentHash([99; 32]))] {
            handler(&node)
                .handle_event(failed(id, failure_hash))
                .await
                .unwrap();
            assert_eq!(
                node.payment(&id).unwrap(),
                receipt,
                "late failure altered receipt"
            );
            assert!(
                node.next_event().is_none(),
                "contradictory failure event escaped"
            );
        }
        receipts.push(receipt);
    }
    drop(node);
    let node = builder.build_with_fs_store().unwrap();
    for receipt in receipts {
        assert_eq!(node.payment(&receipt.id).unwrap(), receipt);
        handler(&node)
            .handle_event(failed(receipt.id, None))
            .await
            .unwrap();
        assert_eq!(node.payment(&receipt.id).unwrap(), receipt);
    }
    assert!(node.next_event().is_none());
}

#[tokio::test]
async fn failure_for_pending_failed_and_missing_records_still_emits_on_replay() {
    let (_dir, builder, _log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let hash = PaymentHash([61; 32]);
    let id = PaymentId([62; 32]);
    node.payment_store
        .insert(PaymentDetails::new(
            id,
            PaymentKind::Spontaneous {
                hash,
                preimage: None,
            },
            Some(10_000),
            None,
            PaymentDirection::Outbound,
            PaymentStatus::Pending,
        ))
        .unwrap();
    // Unchanged Failed and missing records still need event delivery on replay.
    for payment_id in [id, id, PaymentId([63; 32])] {
        handler(&node)
            .handle_event(failed(payment_id, Some(hash)))
            .await
            .unwrap();
        assert_eq!(node.payment(&id).unwrap().status, PaymentStatus::Failed);
        assert!(matches!(node.next_event(), Some(Event::PaymentFailed {
            payment_id: Some(actual), payment_hash: Some(actual_hash), ..
        }) if actual == payment_id && actual_hash == hash));
        node.event_queue.event_handled().await.unwrap();
    }
    assert!(node.payment(&PaymentId([63; 32])).is_none());
}
