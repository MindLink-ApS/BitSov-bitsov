//! Durable recipient offers for paid messages waiting in a sender's outbox.
use konsensus_core::{
    gate::price_with_floor_msat,
    traits::transport::TransportError,
    NodeId,
};
use konsensus_message::{Frame, NoiseTransport};
use konsensus_pricing::peer_prices::{apply_trust_discount, ADMISSION_FLOOR_KEY};
use konsensus_storage::Storage;

/// Persist before publishing: a crash cannot erase a price already offered.
/// No wire change or sender-asserted quote is needed. The gate binds an offer
/// to the sender, kind, and this recipient wallet's verified payment timestamp.
pub(crate) async fn send_price_frame(
    transport: &NoiseTransport,
    storage: &dyn Storage,
    peer: &NodeId,
    frame: &Frame,
    pricing: &dyn konsensus_core::traits::pricing::PricingEngine,
    min_admission_cost_msat: u64,
) -> Result<(), TransportError> {
    if matches!(frame, Frame::PriceTable { block_height: 0, .. } | Frame::PriceResponse { block_height: 0, .. }) {
        return Err(TransportError::Other("konsensus:not_ready:chain_unavailable".into()));
    }
    let mut advertised = frame.clone();
    if let Frame::PriceTable { prices, .. } = &mut advertised {
        prices.insert(ADMISSION_FLOOR_KEY.into(), min_admission_cost_msat);
    }
    let frame = &advertised;
    // A fresh connection has no known advertised discount. Establish one with
    // a full table before a kind response; the sender may retain an old cache.
    let mut initial_table = match frame {
        Frame::PriceTable { .. } => frame.clone(),
        Frame::PriceResponse { block_height, .. } => Frame::PriceTable {
            prices: konsensus_pricing::peer_prices::build_price_table(pricing).await,
            block_height: *block_height,
            valid_blocks: konsensus_pricing::peer_prices::compute_valid_blocks(*block_height),
            trust_discount: 0.0,
        },
        _ => return Err(TransportError::Other("expected a price frame".into())),
    };
    if let Frame::PriceTable { prices, .. } = &mut initial_table {
        prices.insert(ADMISSION_FLOOR_KEY.into(), min_admission_cost_msat);
    }
    let initial_table = &initial_table;
    transport
        .send_price_frame_with(
            peer,
            frame,
            initial_table,
            |discount, needs_table| async move {
                let table = if needs_table {
                    Some(initial_table)
                } else if matches!(frame, Frame::PriceTable { .. }) {
                    Some(frame)
                } else {
                    None
                };
                let mut prices = Vec::new();
                let excluded_kinds = if let Some(Frame::PriceTable {
                    prices: categories, ..
                }) = table
                {
                    prices.extend(
                        categories
                            .iter()
                            .filter(|(category, _)| category.as_str() != ADMISSION_FLOOR_KEY)
                            .map(|(category, price)| {
                                (
                                    // Per-kind entries (`kind:400`) keep their scope.
                                    if category.starts_with("kind:") {
                                        category.clone()
                                    } else {
                                        format!("category:{category}")
                                    },
                                    advertised_price(*price, discount, min_admission_cost_msat),
                                )
                            }),
                    );
                    pricing.category_price_overrides().ok_or_else(|| {
                        TransportError::Other(
                            "pricing engine cannot bind category offer applicability".into(),
                        )
                    })?
                } else {
                    Vec::new()
                };
                if let Frame::PriceResponse {
                    kind, price_msat, ..
                } = frame
                {
                    // Keep the wire price raw: PeerPriceCache retains the table discount
                    // and applies it once, then the admission floor. The durable offer
                    // stores that same final price.
                    prices.push((
                        format!("kind:{kind}"),
                        advertised_price(*price_msat, discount, min_admission_cost_msat),
                    ));
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| TransportError::Other(e.to_string()))?
                    .as_secs();
                storage
                    .record_delivery_prices(
                        peer,
                        &prices,
                        &excluded_kinds,
                        now,
                        now.saturating_add(konsensus_core::gate::DELIVERY_PRICE_WINDOW_SECS),
                    )
                    .await
                    .map_err(|e| TransportError::Other(format!("persist offered prices: {e}")))
            },
        )
        .await
}

fn advertised_price(base: u64, discount: f64, admission: u64) -> u64 {
    let discounted = apply_trust_discount(base, discount);
    price_with_floor_msat(discounted, admission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discounted_offer_applies_admission_floor() {
        for (admission, expected) in [(0, 1000), (2000, 2000)] {
            assert_eq!(
                advertised_price(1000, 0.5, admission),
                expected
            );
        }
    }

    #[tokio::test]
    async fn advertised_prices_pass_gate_for_every_kind() {
        use konsensus_core::{
            gate::{GateConfig, PaymentGate},
            identity::NodeIdentity,
            PaymentProof, Recipient, Signature, UkmEnvelopeBuilder,
        };
        use konsensus_pricing::{peer_prices::PeerPriceEntry, StaticPricingConfig, StaticPricingEngine};
        use sha2::{Digest, Sha256};
        use std::time::Instant;

        let sender = NodeIdentity::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        ).unwrap();
        let preimage = [42; 32];
        let payment_hash = Sha256::digest(preimage).into();
        for base in [1, 1000, 3001] {
            let pricing = StaticPricingEngine::new(StaticPricingConfig {
                chat_msat: base,
                longform_msat: base,
                calendar_msat: base,
                file_ref_msat: base,
                control_msat: base,
                collaboration_msat: base,
                realtime_signal_msat: base,
                call_msat: base,
                app_ext_msat: base,
                web_content_msat: base,
                relay_storage_msat: base,
            });
            for admission in [0, 2000] {
                let gate = PaymentGate::with_config(GateConfig {
                    min_admission_cost_msat: admission,
                    ..Default::default()
                });
                for discount in [0.0, 0.5] {
                    let mut prices = konsensus_pricing::peer_prices::build_price_table(&pricing).await;
                    // Relay storage is advertised separately from the standard table.
                    prices.insert("relay_storage".into(), base);
                    prices.insert(ADMISSION_FLOOR_KEY.into(), admission);
                    let entry = PeerPriceEntry {
                        prices,
                        block_height: 1,
                        valid_blocks: 144,
                        received_at: Instant::now(),
                        trust_discount: discount,
                    };
                    // Exercise every u16 kind through both advert paths. Gate-check
                    // every built-in kind plus the extension range's endpoints;
                    // interior extension kinds share the same category price.
                    for kind in 0..=u16::MAX {
                        let Some(cached) = entry.get_discounted_price_for_kind(kind) else {
                            assert!((700..900).contains(&kind), "missing advert for kind={kind}");
                            continue; // Reserved kinds have no advertised price.
                        };
                        let offered = advertised_price(base, discount, admission);
                        assert_eq!(cached, offered, "kind={kind}, base={base}, discount={discount}, admission={admission}");
                        assert!(offered >= 1000 && offered >= admission);
                        if kind > 1000 && kind < u16::MAX {
                            assert_eq!(entry.get_discounted_price_for_kind(1000), Some(offered));
                            continue;
                        }
                        let mut envelope = UkmEnvelopeBuilder::new(
                            kind,
                            *sender.node_id(),
                            Recipient::Node(NodeId::from_bytes([7; 32])),
                            vec![1],
                            PaymentProof::new(payment_hash, preimage, offered),
                        ).build();
                        envelope.signature = Signature::from_ed25519(&sender.sign(&envelope.signable_bytes()));
                        let result = gate.validate_paid_envelope(
                            &envelope, &pricing, None, None, discount, None,
                        ).await;
                        assert!(result.is_ok(), "kind={kind}, base={base}, discount={discount}, admission={admission}: {result:?}");
                    }
                }
            }
        }
    }
}
