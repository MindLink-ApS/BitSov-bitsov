//! Runtime regressions for the 0.7.1 security backports. No node is started.
#[path = "security_071_payment_status.rs"]
mod payment_status;

use super::*;
use bitcoin::hashes::{sha256, Hash};
use lightning::blinded_path::payment::Bolt12OfferContext;
use lightning::ln::channelmanager::RecipientOnionFields;
use lightning::offers::{invoice_request::InvoiceRequestFields, offer::OfferId};

async fn check_unregistered_skim(is_offer: bool) {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    for skim in [1, 0] {
        let preimage = PaymentPreimage([if skim == 0 { 11 } else { 12 }; 32]);
        let hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
        let purpose = if is_offer {
            PaymentPurpose::Bolt12OfferPayment {
                payment_preimage: Some(preimage),
                payment_secret: PaymentSecret([13; 32]),
                payment_context: Bolt12OfferContext {
                    offer_id: OfferId([14; 32]),
                    invoice_request: InvoiceRequestFields {
                        payer_signing_pubkey: node.node_id(),
                        quantity: None,
                        payer_note_truncated: None,
                        human_readable_name: None,
                    },
                },
            }
        } else {
            PaymentPurpose::SpontaneousPayment(preimage)
        };
        log.0.lock().unwrap().clear();
        handler(&node)
            .handle_event(claimable(hash, purpose, 10_000, skim))
            .await
            .unwrap();
        assert_eq!(
            node.payment(&PaymentId(hash.0)).is_some(),
            skim == 0,
            "an unauthorized skim must be rejected before inserting a receive record"
        );
        assert_eq!(
            reached_claim(&log),
            skim == 0,
            "unauthorized skim reached claim_funds"
        );
        if skim > 0 {
            assert!(log
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.contains("without a corresponding JIT-channel payment")));
        }
        assert!(node.next_event().is_none());
    }
}

#[tokio::test]
async fn keysend_without_record_rejects_skim_but_accepts_zero() {
    check_unregistered_skim(false).await;
}

#[tokio::test]
async fn bolt12_offer_without_record_rejects_skim_but_accepts_zero() {
    check_unregistered_skim(true).await;
}

#[tokio::test]
async fn unknown_even_tlv_never_exposes_manual_claim_but_odd_tlv_does() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    for tlv in [5482373482, 5482373483] {
        let hash = PaymentHash([if tlv % 2 == 0 { 21 } else { 22 }; 32]);
        let secret = PaymentSecret([23; 32]);
        node.payment_store
            .insert(PaymentDetails::new(
                PaymentId(hash.0),
                PaymentKind::Bolt11 {
                    hash,
                    preimage: None,
                    secret: Some(secret),
                },
                Some(10_000),
                None,
                PaymentDirection::Inbound,
                PaymentStatus::Pending,
            ))
            .unwrap();
        let purpose = PaymentPurpose::Bolt11InvoicePayment {
            payment_preimage: None,
            payment_secret: secret,
        };
        let mut event = claimable(hash, purpose, 10_000, 0);
        if let LdkEvent::PaymentClaimable { onion_fields, .. } = &mut event {
            *onion_fields = Some(
                RecipientOnionFields::secret_only(secret)
                    .with_custom_tlvs(vec![(tlv, vec![1, 2, 3])])
                    .unwrap(),
            );
        }
        log.0.lock().unwrap().clear();
        handler(&node).handle_event(event).await.unwrap();
        if tlv % 2 == 0 {
            assert!(
                node.next_event().is_none(),
                "unclaimable required TLV exposed to application"
            );
            assert!(log
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.contains("unknown required TLVs")));
        } else {
            assert!(
                matches!(node.next_event(), Some(Event::PaymentClaimable { payment_hash, .. }) if payment_hash == hash)
            );
        }
        assert_eq!(
            node.payment(&PaymentId(hash.0)).unwrap().status,
            PaymentStatus::Pending
        );
    }
}

#[tokio::test]
async fn successful_send_keeps_preimage_in_receipt_but_never_logs_it() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let preimage = PaymentPreimage([31; 32]);
    let hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
    let id = PaymentId([32; 32]);
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
    for fee in [Some(42), None] {
        log.0.lock().unwrap().clear();
        handler(&node)
            .handle_event(LdkEvent::PaymentSent {
                payment_id: Some(id),
                payment_preimage: preimage,
                payment_hash: hash,
                fee_paid_msat: fee,
                amount_msat: Some(10_000),
                bolt12_invoice: None,
            })
            .await
            .unwrap();
        let entries = log.0.lock().unwrap();
        assert!(entries
            .iter()
            .any(|s| s.contains("Successfully sent payment")
                && s.contains(&hex_utils::to_string(&hash.0))));
        assert!(
            !entries
                .iter()
                .any(|s| s.contains(&hex_utils::to_string(&preimage.0))),
            "preimage leaked to logger"
        );
        drop(entries);
        let stored = node.payment(&id).unwrap();
        assert_eq!(stored.status, PaymentStatus::Succeeded);
        assert!(
            matches!(stored.kind, PaymentKind::Spontaneous { preimage: Some(p), .. } if p == preimage)
        );
        assert!(
            matches!(node.next_event(), Some(Event::PaymentSuccessful { payment_preimage: Some(p), .. }) if p == preimage)
        );
        node.event_queue.event_handled().await.unwrap();
    }
}

#[path = "security_071_circular.rs"]
mod circular_payment;
