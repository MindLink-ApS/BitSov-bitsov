//! Quote-first paid disclosure. Policy is evaluated before any invoice exists.
//! The signed quote seals the promised records to this node; redemption never
//! consults mutable policy, the registry, or live prices. No pending quote state
//! is needed, including across restarts. The normal gate consumes payment once.
use crate::config::{PeerExchangeMode, PrivacyConfig};
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit};
use konsensus_core::{
    gate::{GateConfig, NonceStore, PaymentGate},
    identity::NodeIdentity,
    kind::{KindCategory, KIND_PEER_EXCHANGE},
    traits::{
        lightning::LightningProvider,
        pricing::{PricingEngine, PricingError},
    },
    types::{NodeId, Recipient, Signature},
    UkmEnvelope,
};
use konsensus_message::{
    peer::PeerRegistry,
    wire::{PeerExchangeEntry, PeerExchangeQuote, SovereigntyTier},
    Frame,
};

pub(crate) fn now() -> u64 {
    #[cfg(test)]
    if let Ok(now) = tests::CLOCK.try_with(|now| *now) {
        return now;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cipher(identity: &NodeIdentity) -> Aes256Gcm {
    let key = blake3::derive_key("bitsov peer exchange snapshot v1", identity.aes_key());
    Aes256Gcm::new_from_slice(&key).expect("32-byte AES key")
}

fn description(snapshot: &[u8]) -> String {
    format!(
        "bitsov:peer-exchange:903:{}",
        blake3::hash(snapshot).to_hex()
    )
}

/// All policy decisions precede invoice creation. The session worker separately
/// bounds quote frequency and cardinality before calling this function.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_quote(
    policy: &PrivacyConfig,
    registry: &tokio::sync::RwLock<PeerRegistry>,
    requester: NodeId,
    identity: &NodeIdentity,
    pricing: &dyn PricingEngine,
    floor: u64,
    lightning: &dyn LightningProvider,
) -> Result<PeerExchangeQuote, String> {
    if policy.peer_exchange != PeerExchangeMode::Paid {
        return Err("peer_exchange_off".into());
    }
    let peers: Vec<_> = registry
        .read()
        .await
        .all()
        .iter()
        .filter(|p| {
            p.node_id != requester
                && p.node_id != *identity.node_id()
                && policy.shareable_peers.contains(&p.node_id)
        })
        .take(50)
        .map(|p| PeerExchangeEntry {
            node_id: p.node_id,
            addr: p.addr,
            label: policy
                .share_peer_labels
                .contains(&p.node_id)
                .then(|| p.label.clone())
                .flatten(),
            tier: SovereigntyTier::T1,
        })
        .collect();
    if peers.is_empty() {
        return Err("no_shareable_peers".into());
    }
    if peers.iter().any(|p| {
        p.label
            .as_ref()
            .is_some_and(|l| l.len() > konsensus_message::wire::MAX_PEER_LABEL_BYTES)
    }) {
        return Err("peer_label_too_long".into());
    }
    let plain =
        serde_json::to_vec(&Frame::PeerExchangeResponse { peers }).map_err(|e| e.to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
    let mut snapshot = nonce.to_vec();
    snapshot.extend(
        cipher(identity)
            .encrypt(&nonce, plain.as_slice())
            .map_err(|_| "snapshot encryption failed")?,
    );
    if snapshot.len() > 24576 {
        return Err("snapshot_too_large".into());
    }
    let amount_msat = pricing
        .get_price_msat(KIND_PEER_EXCHANGE)
        .await
        .map_err(|e| e.to_string())?
        .max(floor)
        .max(1000);
    let expires_at = now() + 60;
    let memo = description(&snapshot);
    // Reserve five seconds for RPC completion. Unsupported backends fail closed;
    // never fall back to persistent unpaid invoices.
    let invoice = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        lightning.create_stateless_invoice(amount_msat, &memo, 55),
    )
    .await
    .map_err(|_| "quote_backend_timeout")?
    .map_err(|e| e.to_string())?;
    let signed = invoice
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|_| "invalid_invoice")?;
    if invoice.bolt11.len() > 8192
        || signed.amount_milli_satoshis() != Some(amount_msat)
        || signed.description().to_string() != memo
        || signed.payment_hash().to_string() != invoice.payment_hash
        || signed.duration_since_epoch().as_secs() > now()
        || signed.is_expired()
        || signed
            .expires_at()
            .is_none_or(|end| end.as_secs() > expires_at)
    {
        return Err("invalid_invoice".into());
    }
    let mut quote = PeerExchangeQuote {
        recipient: *identity.node_id(),
        requester,
        expires_at,
        amount_msat,
        snapshot,
        bolt11: invoice.bolt11,
        signature: Signature::from_bytes([0; 64]),
    };
    quote.signature = Signature::from_ed25519(&identity.sign(&quote.signable_bytes()));
    Ok(quote)
}

/// Authenticate and open the quote BEFORE asking the gate to accept payment.
/// Only a matching, fresh, settled proof can consume the durable replay keys.
pub(crate) async fn redeem(
    quote: &PeerExchangeQuote,
    envelope: &UkmEnvelope,
    peer: &NodeId,
    identity: &NodeIdentity,
    nonces: &dyn NonceStore,
    lightning: &dyn LightningProvider,
) -> Result<Vec<PeerExchangeEntry>, String> {
    if quote.recipient != *identity.node_id()
        || quote.requester != *peer
        || now() >= quote.expires_at
        || quote.expires_at > now().saturating_add(60)
        || quote.snapshot.len() < 12
        || quote.snapshot.len() > 24576
        || quote.amount_msat == 0
        || identity
            .verify(&quote.signable_bytes(), &quote.signature.to_ed25519())
            .is_err()
    {
        return Err("invalid_peer_exchange_quote".into());
    }
    let invoice = quote
        .bolt11
        .parse::<lightning_invoice::Bolt11Invoice>()
        .map_err(|_| "invalid_invoice")?;
    if envelope.kind != KIND_PEER_EXCHANGE
        || envelope.sender != *peer
        || envelope.recipient != Recipient::Node(*identity.node_id())
        || envelope.ciphertext != quote.signature.as_bytes()
        || envelope.payment_proof.amount_msat != quote.amount_msat
        || hex::encode(envelope.payment_proof.payment_hash) != invoice.payment_hash().to_string()
        || invoice.amount_milli_satoshis() != Some(quote.amount_msat)
        || invoice.description().to_string() != description(&quote.snapshot)
    {
        return Err("quote_payment_mismatch".into());
    }
    let (nonce, encrypted) = quote.snapshot.split_at(12);
    let plain = cipher(identity)
        .decrypt(aes_gcm::Nonce::from_slice(nonce), encrypted)
        .map_err(|_| "invalid_snapshot")?;
    let Frame::PeerExchangeResponse { peers } =
        serde_json::from_slice(&plain).map_err(|_| "invalid_snapshot")?
    else {
        return Err("invalid_snapshot".into());
    };
    // Membership and policy were resolved at quote issuance. Freeze the tariff,
    // including the admission floor; never refuse a paid quote on repricing.
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    gate.verify(
        envelope,
        nonces,
        &QuotedPrice(quote.amount_msat),
        None,
        Some(lightning),
        0.0,
        Some(identity.node_id()),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(peers)
}

struct QuotedPrice(u64);
#[async_trait::async_trait]
impl PricingEngine for QuotedPrice {
    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError> {
        if kind == KIND_PEER_EXCHANGE {
            Ok(self.0)
        } else {
            Err(PricingError::NotPriceable(kind))
        }
    }
    async fn get_category_price_msat(&self, _: KindCategory) -> Result<u64, PricingError> {
        Err(PricingError::Other("quote applies to one act only".into()))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
#[path = "tests/peer_exchange.rs"]
mod tests;
