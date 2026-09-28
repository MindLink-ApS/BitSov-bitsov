//! Durable recipient offers for paid messages waiting in a sender's outbox.
use konsensus_core::{traits::transport::TransportError, NodeId};
use konsensus_message::{Frame, NoiseTransport};
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
    let excluded_kinds = if matches!(frame, Frame::PriceTable { .. }) {
        pricing.category_price_overrides().ok_or_else(|| {
            TransportError::Other("pricing engine cannot bind category offer applicability".into())
        })?
    } else {
        Vec::new()
    };
    let prices = match frame {
        Frame::PriceTable {
            prices,
            trust_discount,
            ..
        } => prices
            .iter()
            .map(|(category, price)| {
                (
                    format!("category:{category}"),
                    konsensus_pricing::peer_prices::apply_trust_discount(*price, *trust_discount),
                )
            })
            .collect::<Vec<_>>(),
        Frame::PriceResponse {
            kind, price_msat, ..
        } => vec![(format!("kind:{kind}"), (*price_msat).max(1))],
        _ => return Err(TransportError::Other("expected a price frame".into())),
    };
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
        .map_err(|e| TransportError::Other(format!("persist offered prices: {e}")))?;
    transport.send_frame(peer, frame).await
}
