// Compatibility oracle from main 696d57a4e7c427a086538118933e6a562132050d.
#[allow(clippy::too_many_arguments)]
async fn baseline_invoice_requested_gated(
    peer_id: &NodeId,
    request_id: &str,
    amount_msat: u64,
    purpose: &str,
    privileged: bool,
    pricing: &Arc<dyn konsensus_core::traits::pricing::PricingEngine>,
    lightning: &Arc<dyn LightningProvider>,
    transport: &Arc<NoiseTransport>,
    recipient: &NodeId,
    source_ip: std::net::IpAddr,
    quotes: &mut legacy_quotes::AdmissionQuotes,
    membrane: &konsensus_api::membrane::Membrane,
    last_admission_refusal: &mut crate::invoice_refusals::RefusalLimits,
) {
    use konsensus_core::admission_quote;
    if purpose == admission_quote::PURPOSE {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !quotes.permit(
            source_ip,
            recipient,
            peer_id,
            request_id,
            tokio::time::Instant::now(),
            unix,
        ) {
            if last_admission_refusal.permit(source_ip, tokio::time::Instant::now()) {
                send_invoice_refusal(transport, peer_id, request_id, konsensus_api::invoice_refusal::ADMISSION_RATE_LIMITED).await;
            }
            return;
        }
        // Exactly the first-contact chat price. Neither kind nor amount is
        // requester-selected. No peer/storage/session dependency is present.
        let Ok(Ok(price)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pricing.get_price_msat(ADMISSION_INVOICE_KIND),
        )
        .await
        else {
            return;
        };
        // Same rule as the signed introduction's display prices.
        let (admission, message) = konsensus_core::introduction::first_contact_prices(price);
        let description = format!("konsensus:{request_id}:message={message}");
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let Some(attempt_end) = admission_quote::expires_at(request_id, recipient, peer_id, unix)
        else {
            return;
        };
        // Reserve the entire backend RPC budget, since its invoice timestamp
        // may be assigned near the end of that call, not at our request time.
        let expiry = attempt_end.saturating_sub(unix).saturating_sub(5) as u32;
        if expiry == 0 {
            return;
        }
        let invoice = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lightning.create_stateless_invoice(admission, &description, expiry),
        )
        .await;
        if matches!(&invoice, Ok(Err(konsensus_core::traits::lightning::LightningError::StatelessQuoteUnsupported))) {
            let refusal = Frame::InvoiceError {
                request_id: request_id.into(),
                reason: "stateless_quote_unsupported".into(),
            };
            if last_admission_refusal.permit(source_ip, tokio::time::Instant::now()) {
                let _ = transport.enqueue_control_frame(peer_id, &refusal).await;
            }
            return;
        }
        if let Ok(Ok(invoice)) = invoice {
            let Ok(signed) = invoice.bolt11.parse::<lightning_invoice::Bolt11Invoice>() else {
                return;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            if signed.duration_since_epoch() > now
                || signed.is_expired()
                || signed
                    .expires_at()
                    .is_none_or(|end| end.as_secs() > attempt_end)
                || signed.amount_milli_satoshis() != Some(admission)
                || signed.description().to_string() != description
                || signed.payment_hash().to_string() != invoice.payment_hash
            {
                return;
            }
            // The only response is the recipient's price (inside BOLT11) and
            // invoice. An unpaid quote never promotes the connection.
            let response = Frame::InvoiceResponse {
                request_id: request_id.into(),
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
            };
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                transport.send_frame(peer_id, &response),
            )
            .await;
        }
        return;
    }
    if !privileged {
        let now = tokio::time::Instant::now();
        if last_admission_refusal.permit(source_ip, now) {
            last_admission_refusal.event(peer_id, now, membrane);
            send_invoice_refusal(transport, peer_id, request_id, konsensus_api::invoice_refusal::ADMISSION_REQUIRED).await;
        }
        return;
    }
    // Old arbitrary-kind/legacy admission requests fail closed, even if paid.
    if privileged && !purpose.starts_with(ADMISSION_INVOICE_PURPOSE) {
        handle_invoice_requested(
            peer_id,
            request_id,
            amount_msat,
            purpose,
            lightning,
            transport,
            source_ip,
            last_admission_refusal,
        )
        .await;
    }
}
