//! Durable recipient offers for paid messages waiting in a sender's outbox.
use konsensus_core::{
    gate::porch_read_floor_msat,
    kind::{KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE},
    traits::transport::TransportError,
    NodeId,
};
use konsensus_message::{Frame, NoiseTransport};
use konsensus_pricing::peer_prices::apply_trust_discount;
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
) -> Result<(), TransportError> {
    // A fresh connection has no known advertised discount. Establish one with
    // a full table before a kind response; the sender may retain an old cache.
    let initial_table = match frame {
        Frame::PriceTable { .. } => frame.clone(),
        Frame::PriceResponse { block_height, .. } => Frame::PriceTable {
            prices: konsensus_pricing::peer_prices::build_price_table(pricing).await,
            block_height: *block_height,
            valid_blocks: konsensus_pricing::peer_prices::compute_valid_blocks(*block_height),
            trust_discount: 0.0,
        },
        _ => return Err(TransportError::Other("expected a price frame".into())),
    };
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
                    prices.extend(categories.iter().map(|(category, price)| {
                        let floor = category
                            .strip_prefix("kind:")
                            .and_then(|kind| kind.parse::<u16>().ok())
                            .map(porch_read_floor_msat)
                            .unwrap_or(0);
                        (
                            // Per-kind entries (`kind:400`) keep their scope.
                            if category.starts_with("kind:") {
                                category.clone()
                            } else {
                                format!("category:{category}")
                            },
                            apply_trust_discount(*price, discount).max(floor),
                        )
                    }));
                    let mut excluded = pricing.category_price_overrides().ok_or_else(|| {
                        TransportError::Other(
                            "pricing engine cannot bind category offer applicability".into(),
                        )
                    })?;
                    // The rest of web_content retains its discounted price. Bind
                    // porch reads separately, excluding them from the cheaper
                    // category quote (the store resolves the minimum offer).
                    for kind in [KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE] {
                        let key = format!("kind:{kind}");
                        if !categories.contains_key(&key) && !excluded.contains(&kind) {
                            if let Some(base) = categories.get("web_content") {
                                prices.push((
                                    key,
                                    apply_trust_discount(*base, discount)
                                        .max(porch_read_floor_msat(kind)),
                                ));
                            }
                        }
                        if !excluded.contains(&kind) {
                            excluded.push(kind);
                        }
                    }
                    excluded
                } else {
                    Vec::new()
                };
                if let Frame::PriceResponse {
                    kind, price_msat, ..
                } = frame
                {
                    // Keep the wire price raw: PeerPriceCache retains the table discount
                    // and applies it once, then the porch floor. The durable offer
                    // stores that same final price.
                    prices.push((
                        format!("kind:{kind}"),
                        apply_trust_discount(*price_msat, discount)
                            .max(porch_read_floor_msat(*kind)),
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
