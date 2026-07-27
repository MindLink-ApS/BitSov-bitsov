//! Payment Gate — fail-closed enforcement of Principle 2.
//!
//! Every incoming UKM envelope must pass through this gate before being
//! accepted. The gate enforces:
//!
//! 1. **Envelope integrity** — ID matches, ciphertext non-empty, preimage valid
//! 2. **Whitelist check** — sender must be in the federation whitelist (Principle 3)
//! 3. **Signature verification** — Ed25519 signature is valid for sender's key
//! 4. **Nonce replay protection** — nonce has never been seen before
//! 5. **Price verification** — payment amount meets the required price for this kind
//! 6. **Payment settlement** — optionally verify settlement via Lightning backend
//!
//! **FAIL-CLOSED**: Any verification failure results in rejection. If the
//! Lightning backend is unreachable, the message is rejected. If the pricing
//! engine fails, the message is rejected. There is no fallback. This is not
//! configurable. Principle 2 is not negotiable.

use std::collections::HashSet;

use ed25519_dalek::Verifier;
use thiserror::Error;
use tracing::{debug, instrument, warn};

use crate::envelope::UkmEnvelope;
use crate::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};
use crate::traits::pricing::{PricingEngine, PricingError};
use crate::types::{MessageId, NodeId, Nonce, Recipient};

/// Why the gate rejected a message.
///
/// Every variant is a hard rejection — the message MUST NOT be accepted.
#[derive(Debug, Error)]
pub enum GateRejection {
    /// Envelope failed structural validation (bad ID, empty ciphertext, bad preimage).
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// The sender is not in the federation whitelist (Principle 3: closed mesh).
    #[error("sender {0} not whitelisted")]
    NotWhitelisted(NodeId),

    /// Ed25519 signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Message timestamp is too old.
    #[error("message too old: age {age_ms} ms exceeds max {max_ms} ms")]
    MessageTooOld {
        /// Actual age of the message in milliseconds.
        age_ms: u64,
        /// Maximum allowed age in milliseconds.
        max_ms: u64,
    },

    /// Message timestamp is too far in the future.
    #[error("message from future: {ahead_ms} ms ahead exceeds max {max_ms} ms")]
    MessageFromFuture {
        /// How far ahead the message timestamp is (milliseconds).
        ahead_ms: u64,
        /// Maximum allowed future offset (milliseconds).
        max_ms: u64,
    },

    /// Nonce has been seen before — this is a replay attack.
    #[error("replay detected: nonce already used")]
    ReplayDetected,

    /// Nonce storage check failed (storage error = rejection, fail-closed).
    #[error("nonce check failed: {0}")]
    NonceCheckFailed(String),

    /// Payment amount is less than the required price.
    #[error("insufficient payment: required {required_msat} msat, got {paid_msat} msat")]
    InsufficientPayment {
        /// Price required for this message kind.
        required_msat: u64,
        /// Amount actually paid.
        paid_msat: u64,
    },

    /// Pricing engine failed (fail-closed: if we can't determine price, reject).
    #[error("pricing failed: {0}")]
    PricingFailed(String),

    /// Payment not settled on Lightning backend (optional verification).
    #[error("payment not settled: {0}")]
    PaymentNotSettled(String),

    /// Settled Lightning payment details do not match the envelope proof.
    #[error("payment settlement mismatch: {0}")]
    PaymentSettlementMismatch(String),

    /// The same settled Lightning payment hash was already accepted.
    #[error("payment proof already used: {payment_hash}")]
    PaymentProofReused {
        /// Hex-encoded Lightning payment hash.
        payment_hash: String,
    },

    /// Lightning backend unreachable (fail-closed: if we can't verify, reject).
    #[error("lightning verification failed: {0}")]
    LightningUnavailable(String),

    /// Message kind is not priceable and no valid session exists to cover it.
    /// Fail-closed: reject until the feature has an explicit price.
    #[error("kind {0} is not priceable and has no covering session")]
    KindNotPriceable(u16),

    /// The settled payment was addressed to a different node — admission proof
    /// is non-transferable (defense-in-depth on top of direction/amount/preimage).
    #[error("recipient mismatch: envelope addressed to {claimed}, this node is {ours}")]
    RecipientMismatch {
        /// The recipient NodeId the signed envelope claims.
        claimed: NodeId,
        /// This node's own NodeId.
        ours: NodeId,
    },

}

/// Trait for nonce replay protection storage.
///
/// Extracted from the full Storage trait so the gate can live in konsensus-core
/// without depending on konsensus-storage.
#[async_trait::async_trait]
pub trait NonceStore: Send + Sync {
    /// Store a nonce and return whether it was new.
    ///
    /// Returns `Ok(true)` if the nonce was new (first time seen).
    /// Returns `Ok(false)` if the nonce already existed (replay detected).
    /// Returns `Err` on storage failure.
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    /// Store an accepted Lightning payment hash and return whether it was new.
    ///
    /// Nonces stop identical envelope replays. Payment hashes stop the more
    /// important economic replay: one settled payment proof reused across fresh
    /// envelopes with different nonces.
    ///
    /// **FAIL-CLOSED DEFAULT.** This default deliberately returns an error
    /// rather than `Ok(true)`. Economic replay protection is money-path
    /// (Principle 2): a permissive default would silently turn the Step-7
    /// payment-proof replay check in [`PaymentGate::verify`] into a no-op for
    /// any backend that forgets to override this method, letting one settled
    /// Lightning payment buy unlimited fresh-nonce envelopes. Returning an
    /// error makes that mistake loud and safe — the gate rejects with
    /// `NonceCheckFailed` instead of accepting an unpaid replay. Every
    /// production `NonceStore` MUST override this with a durable,
    /// insert-or-reject store keyed on the payment hash.
    async fn check_and_store_payment_hash(
        &self,
        _payment_hash: &[u8; 32],
        _sender: &NodeId,
        _message_id: &MessageId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Err("NonceStore::check_and_store_payment_hash not implemented: \
             economic replay protection is fail-closed and must be overridden \
             with a durable payment-hash store"
            .into())
    }
}

/// Configuration for the payment gate.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Maximum age of a message timestamp before rejection (milliseconds).
    /// Default: 5 minutes.
    pub max_message_age_ms: u64,

    /// Maximum allowed future offset for a message timestamp (milliseconds).
    /// Messages timestamped more than this far into the future are rejected.
    /// Prevents hoarding signed+paid messages for later replay after nonce
    /// pruning. Default: 5 minutes.
    pub max_future_ms: u64,

    /// Whether to verify payment settlement via the Lightning backend.
    /// When false, only preimage verification is performed (faster, no network call).
    /// When true, additionally queries the Lightning backend to confirm settlement.
    /// Default: false (preimage proof is cryptographically sufficient).
    pub verify_lightning_settlement: bool,

    /// Absolute minimum admission price in msat (doorway hardening #4).
    ///
    /// The operator-modeled marginal cost of admitting one inbound paid contact
    /// — signature verify + nonce store + Lightning settlement round-trip + the
    /// held connection/session state. The resolved required price is floored at
    /// this value so an attacker can never pay strictly *less* than it costs the
    /// node to process the admission (pay-to-DoS asymmetry). The doorway-membrane
    /// rate-limits (#300) and circuit-breaker (#304) bound the *rate* of such
    /// work; this floor *prices* it.
    ///
    /// Default: `0` (off). With the floor at 0 the price is byte-identical to
    /// pre-#4 behaviour. The floor is fail-closed-direction: it can only ever
    /// *raise* the required amount, never admit something the base price would
    /// have rejected. The value is an operator-economic decision — left at 0
    /// until an operator sets it to their node's measured per-admission cost.
    pub min_admission_cost_msat: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_message_age_ms: 5 * 60 * 1000, // 5 minutes
            max_future_ms: 5 * 60 * 1000,      // 5 minutes
            verify_lightning_settlement: false,
            min_admission_cost_msat: 0, // off: floor disabled, no price change
        }
    }
}

/// The payment gate — Principle 2 enforcement.
///
/// Verifies every incoming UKM envelope against a sequence of checks.
/// Any failure results in rejection. No exceptions, no fallbacks, no bypasses.
pub struct PaymentGate {
    config: GateConfig,
}

impl PaymentGate {
    /// Create a new payment gate with default configuration.
    pub fn new() -> Self {
        Self {
            config: GateConfig::default(),
        }
    }

    /// Create a payment gate with custom configuration.
    pub fn with_config(config: GateConfig) -> Self {
        Self { config }
    }

    /// Verify an incoming UKM envelope.
    ///
    /// This is the central enforcement point for Principle 2. Every check must
    /// pass for the message to be accepted. **FAIL-CLOSED**: any error = rejection.
    ///
    /// # Arguments
    ///
    /// * `envelope` — The incoming message to verify
    /// * `nonce_store` — Storage for replay protection nonces
    /// * `pricing` — Pricing engine to determine required payment
    /// * `whitelist` — If `Some`, the sender must be in this set (Principle 3)
    /// * `lightning` — If configured, used for settlement verification
    /// * `trust_discount` — Plasticity pricing discount for this sender (0.0 to 0.5).
    ///   Based on the sender's synaptic weight in our routing table. Higher weight
    ///   = more reliable peer = lower required payment. Default 0.0 (no discount).
    #[instrument(skip_all, fields(
        sender = %envelope.sender,
        kind = envelope.kind,
        amount_msat = envelope.payment_proof.amount_msat,
    ))]
    #[allow(clippy::too_many_arguments)]
    pub async fn verify(
        &self,
        envelope: &UkmEnvelope,
        nonce_store: &dyn NonceStore,
        pricing: &dyn PricingEngine,
        whitelist: Option<&HashSet<NodeId>>,
        lightning: Option<&dyn LightningProvider>,
        trust_discount: f64,
        // This node's own NodeId. Threaded into settlement to bind the signed
        // `envelope.recipient` to THIS node so a settlement proof for another
        // node is non-transferable. Pass `None` only on the send path, where the
        // envelope is legitimately addressed to a peer.
        our_node_id: Option<&NodeId>,
    ) -> Result<(), GateRejection> {
        // ── Step 1: Envelope integrity ─────────────────────────────────
        // Validates: ID matches blake3(ciphertext||nonce), ciphertext non-empty,
        // preimage matches payment_hash via SHA-256.
        envelope
            .validate()
            .map_err(|e: crate::error::CoreError| GateRejection::InvalidEnvelope(e.to_string()))?;

        debug!("envelope integrity: OK");

        // ── Step 2: Whitelist check (Principle 3: closed mesh) ─────────
        if let Some(allowed) = whitelist {
            if !allowed.contains(&envelope.sender) {
                warn!(sender = %envelope.sender, "rejected: sender not whitelisted");
                return Err(GateRejection::NotWhitelisted(envelope.sender));
            }
        }

        debug!("whitelist check: OK");

        // ── Step 2.5: Timestamp freshness check ─────────────────────────
        // Reject messages that are too old. This prevents an attacker from
        // hoarding valid signed+paid messages and replaying them later
        // (belt-and-suspenders with nonce replay protection).
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let age_ms = now_ms.saturating_sub(envelope.timestamp);
        if age_ms > self.config.max_message_age_ms {
            warn!(
                age_ms,
                max_ms = self.config.max_message_age_ms,
                "rejected: message too old"
            );
            return Err(GateRejection::MessageTooOld {
                age_ms,
                max_ms: self.config.max_message_age_ms,
            });
        }

        // Reject messages timestamped too far into the future. Without this,
        // a message dated year 2030 would pass the age check (age=0 via
        // saturating_sub) and if nonces are ever pruned, it becomes replayable.
        let ahead_ms = envelope.timestamp.saturating_sub(now_ms);
        if ahead_ms > self.config.max_future_ms {
            warn!(
                ahead_ms,
                max_ms = self.config.max_future_ms,
                "rejected: message from future"
            );
            return Err(GateRejection::MessageFromFuture {
                ahead_ms,
                max_ms: self.config.max_future_ms,
            });
        }

        debug!("timestamp freshness: OK");

        // ── Step 3: Ed25519 signature verification ─────────────────────
        // Recover the verifying key from the sender's NodeId and verify
        // the signature over the signable fields.
        self.verify_signature(envelope)?;

        debug!("signature verification: OK");

        // ── Step 4: Nonce replay protection ────────────────────────────
        let is_new = nonce_store
            .check_and_store(&envelope.nonce, &envelope.sender)
            .await
            .map_err(|e| GateRejection::NonceCheckFailed(e.to_string()))?;

        if !is_new {
            warn!("rejected: nonce replay detected");
            return Err(GateRejection::ReplayDetected);
        }

        debug!("nonce replay check: OK");

        // ── Step 5: Price verification ─────────────────────────────────
        // Determine the required price for this message kind and verify
        // the payment amount meets or exceeds it. Plasticity pricing
        // applies a trust discount for reliable peers (v2.1). The resolved
        // `required_msat` (after discount) is threaded into settlement so the
        // price floor is re-enforced there too (Council #218).
        let required_msat = self.verify_price(envelope, pricing, trust_discount).await?;

        debug!("price verification: OK");

        // ── Step 6: Lightning settlement verification (optional) ───────
        // If configured, verify the payment is actually settled on the
        // Lightning backend. This is defense-in-depth — the preimage proof
        // (step 1) is already cryptographically sufficient. Settlement also
        // independently enforces `required_msat`, so it fail-closes on the
        // price floor even if step 5 were ever bypassed or reordered.
        if self.config.verify_lightning_settlement {
            if let Some(ln) = lightning {
                self.verify_settlement(envelope, ln, required_msat, our_node_id)
                    .await?;
                debug!("lightning settlement: OK");
            } else {
                // Configured to verify but no Lightning provider available = reject
                return Err(GateRejection::LightningUnavailable(
                    "settlement verification enabled but no Lightning provider".into(),
                ));
            }
        }

        // ── Step 7: Payment proof replay protection ────────────────────
        // This must run for every accepted paid envelope, even when
        // settlement verification is disabled for mock/local backends. A
        // settled payment hash buys one message, not unlimited fresh nonces.
        let payment_hash_is_new = nonce_store
            .check_and_store_payment_hash(
                &envelope.payment_proof.payment_hash,
                &envelope.sender,
                &envelope.id,
            )
            .await
            .map_err(|e| GateRejection::NonceCheckFailed(format!("payment hash: {e}")))?;

        if !payment_hash_is_new {
            let payment_hash = hex::encode(envelope.payment_proof.payment_hash);
            warn!(%payment_hash, "rejected: payment proof replay detected");
            return Err(GateRejection::PaymentProofReused { payment_hash });
        }

        debug!("gate: ALL CHECKS PASSED — message accepted");
        Ok(())
    }

    /// Verify the Ed25519 signature over the envelope's signable fields.
    fn verify_signature(&self, envelope: &UkmEnvelope) -> Result<(), GateRejection> {
        let verifying_key = envelope
            .sender
            .to_verifying_key()
            .map_err(|e| GateRejection::InvalidSignature(format!("bad sender key: {e}")))?;

        let signable = envelope.signable_bytes();
        let ed_sig = envelope.signature.to_ed25519();

        verifying_key
            .verify(&signable, &ed_sig)
            .map_err(|e: ed25519_dalek::SignatureError| {
                GateRejection::InvalidSignature(e.to_string())
            })
    }

    /// Verify the payment amount meets the required price.
    ///
    /// Applies plasticity trust discount: `required = base * (1 - discount)`.
    /// Discount is clamped to \[0.0, 0.5\] and the minimum price is 1 msat
    /// (payment gate is fail-closed: zero = bypass).
    ///
    /// On success, returns the resolved `required_msat` (after discount) so the
    /// caller can thread the same price floor into the settlement layer
    /// (defense-in-depth: settlement must enforce `required_msat` too, not just
    /// the envelope's self-asserted claim).
    async fn verify_price(
        &self,
        envelope: &UkmEnvelope,
        pricing: &dyn PricingEngine,
        trust_discount: f64,
    ) -> Result<u64, GateRejection> {
        let base_msat = match pricing.get_price_msat(envelope.kind).await {
            Ok(price) => price,
            Err(PricingError::NotPriceable(kind)) => {
                // Fail-closed: reject kinds that have no price.
                warn!(
                    kind,
                    "rejected: kind is not priceable and no covering session exists"
                );
                return Err(GateRejection::KindNotPriceable(kind));
            }
            Err(e) => {
                return Err(GateRejection::PricingFailed(e.to_string()));
            }
        };

        // Apply plasticity trust discount (v2.1): reliable peers pay less.
        // Clamp discount to [0.0, 0.5], enforce minimum 1 msat.
        // Fail-safe: NaN or infinite discount → no discount (full price).
        // NaN bypassing this check would produce 1 msat, weakening the gate.
        let clamped_discount = if trust_discount.is_finite() {
            trust_discount.clamp(0.0, 0.5)
        } else {
            0.0
        };
        let discounted_msat = if clamped_discount > 0.0 {
            let discounted = (base_msat as f64) * (1.0 - clamped_discount);
            (discounted.ceil() as u64).max(1)
        } else {
            base_msat
        };

        if clamped_discount > 0.0 {
            debug!(
                base_msat,
                discounted_msat,
                trust_discount = clamped_discount,
                "plasticity pricing: trust discount applied"
            );
        }

        // Cost floor (doorway hardening #4): the resolved price may never fall
        // below the operator-modeled marginal cost of admitting this contact.
        // Applied AFTER the plasticity discount so a trusted peer's discount can
        // never undercut what it costs to serve them — the floor is an absolute
        // minimum, not a discountable base. Defaults to 0, in which case this
        // `.max()` is a no-op and pricing is byte-identical to pre-#4 behaviour.
        // Fail-closed direction: can only RAISE the required amount. Because the
        // resolved `required_msat` is returned to and re-enforced by the
        // settlement layer, the floor binds the settled amount too — a sender
        // cannot under-claim below cost and pass settlement in isolation.
        let required_msat = discounted_msat.max(self.config.min_admission_cost_msat);

        if required_msat > discounted_msat {
            debug!(
                discounted_msat,
                cost_floor_msat = self.config.min_admission_cost_msat,
                required_msat,
                kind = envelope.kind,
                "cost floor applied: resolved price raised to marginal-cost floor"
            );
        }

        let paid_msat = envelope.payment_proof.amount_msat;

        if paid_msat < required_msat {
            warn!(
                required_msat,
                paid_msat,
                kind = envelope.kind,
                trust_discount = clamped_discount,
                "rejected: insufficient payment"
            );
            return Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            });
        }

        Ok(required_msat)
    }

    /// Verify payment settlement via the Lightning backend.
    ///
    /// Defense-in-depth (Council #218): in addition to checking that the settled
    /// payment is self-consistent with the envelope's own claim, this layer
    /// independently enforces the price floor. The caller passes the resolved
    /// `required_msat` (the same value `verify_price` computed) and settlement
    /// rejects any settled amount below it. This makes settlement a STANDALONE
    /// price-floor enforcer: even if `verify_price` were bypassed, reordered,
    /// or removed, a below-required payment cannot pass the gate through this
    /// path. Fail-closed at EVERY layer.
    async fn verify_settlement(
        &self,
        envelope: &UkmEnvelope,
        lightning: &dyn LightningProvider,
        required_msat: u64,
        our_node_id: Option<&NodeId>,
    ) -> Result<(), GateRejection> {
        let payment_hash = hex::encode(envelope.payment_proof.payment_hash);

        let details = lightning
            .get_payment_status(&payment_hash)
            .await
            .map_err(|e| GateRejection::LightningUnavailable(e.to_string()))?;

        if details.status != PaymentStatus::Settled {
            return Err(GateRejection::PaymentNotSettled(format!(
                "payment status: {:?}",
                details.status
            )));
        }

        let returned_hash = decode_hex_32("payment_hash", &details.payment_hash)?;
        if returned_hash != envelope.payment_proof.payment_hash {
            return Err(GateRejection::PaymentSettlementMismatch(
                "backend returned a different payment hash".into(),
            ));
        }

        if details.direction != PaymentDirection::Incoming {
            return Err(GateRejection::PaymentSettlementMismatch(format!(
                "payment direction is {:?}, expected incoming",
                details.direction
            )));
        }

        // ── Recipient binding (admission proof is non-transferable) ──────
        // The settlement record (PaymentDetails) carries no payee field, so a
        // valid Incoming settlement for node B could otherwise be replayed as
        // proof for node A. Bind the SIGNED `envelope.recipient` (covered by
        // `signable_bytes`, so a sender cannot alter it post-signing) to THIS
        // node's identity. Defense-in-depth ON TOP of direction + amount +
        // required_msat + preimage — never replacing them (the pre-existing
        // `direction == Incoming` check against this node's own backend is the
        // primary cross-node-replay closer; this makes the addressee explicit
        // and fail-closed). Room/Broadcast have no single payee, so binding is
        // N/A there (rooms route per-member with individual proofs; Broadcast is
        // disabled on launch nodes) and the direction/price/preimage checks
        // remain the enforcers.
        if let Recipient::Node(claimed) = envelope.recipient {
            match our_node_id {
                Some(ours) if *ours == claimed => { /* payee bound to this node */ }
                Some(ours) => {
                    warn!(
                        %claimed,
                        ours = %ours,
                        "rejected: settlement proof addressed to a different node"
                    );
                    return Err(GateRejection::RecipientMismatch {
                        claimed,
                        ours: *ours,
                    });
                }
                None => {
                    // No identity supplied => recipient binding is not requested
                    // for this call (e.g. the send path, where the envelope is
                    // addressed to a peer, not this node). The direction==Incoming
                    // + price-floor + preimage checks remain the enforcers. The
                    // production RECEIVE path always passes Some(identity), so the
                    // admission binding is active where an attacker's replayed
                    // proof would actually be checked.
                }
            }
        }

        if details.amount_msat < envelope.payment_proof.amount_msat {
            return Err(GateRejection::PaymentSettlementMismatch(format!(
                "settled amount {} msat is below envelope claim {} msat",
                details.amount_msat, envelope.payment_proof.amount_msat
            )));
        }

        // Independent price-floor enforcement (Council #218 deeper fix). The
        // amount-consistency check above only binds the settled amount to the
        // envelope's *self-asserted* claim, so a sender could under-claim to
        // lower the price and still pass settlement in isolation. Bind the
        // settled amount to the kind's resolved `required_msat` directly so the
        // settlement layer alone fail-closes on the price floor — no reliance on
        // `verify_price` having run first.
        if details.amount_msat < required_msat {
            warn!(
                required_msat,
                settled_msat = details.amount_msat,
                "rejected: settled amount below required price"
            );
            return Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat: details.amount_msat,
            });
        }

        let Some(preimage_hex) = details.preimage.as_deref() else {
            return Err(GateRejection::PaymentSettlementMismatch(
                "settled payment has no preimage".into(),
            ));
        };
        let returned_preimage = decode_hex_32("preimage", preimage_hex)?;
        if returned_preimage != envelope.payment_proof.preimage {
            return Err(GateRejection::PaymentSettlementMismatch(
                "backend preimage does not match envelope proof".into(),
            ));
        }

        Ok(())
    }
}

fn decode_hex_32(field: &str, value: &str) -> Result<[u8; 32], GateRejection> {
    hex::decode(value)
        .map_err(|e| {
            GateRejection::PaymentSettlementMismatch(format!("{field}: invalid hex: {e}"))
        })?
        .try_into()
        .map_err(|_| GateRejection::PaymentSettlementMismatch(format!("{field}: wrong length")))
}

impl Default for PaymentGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UkmEnvelopeBuilder;
    use crate::identity::NodeIdentity;
    use crate::kind::{KIND_CHAT, KindCategory};
    use crate::traits::lightning::{Invoice, LightningError, PaymentDetails, PaymentDirection};
    use crate::types::{PaymentProof, Recipient};
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    // ── Mock NonceStore ────────────────────────────────────────────────

    struct MockNonceStore {
        seen: Mutex<HashSet<[u8; 24]>>,
        seen_payment_hashes: Mutex<HashSet<[u8; 32]>>,
    }

    impl MockNonceStore {
        fn new() -> Self {
            Self {
                seen: Mutex::new(HashSet::new()),
                seen_payment_hashes: Mutex::new(HashSet::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl NonceStore for MockNonceStore {
        async fn check_and_store(
            &self,
            nonce: &Nonce,
            _sender: &NodeId,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let mut seen = self.seen.lock().unwrap();
            Ok(seen.insert(*nonce.as_bytes()))
        }

        async fn check_and_store_payment_hash(
            &self,
            payment_hash: &[u8; 32],
            _sender: &NodeId,
            _message_id: &crate::MessageId,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let mut seen = self.seen_payment_hashes.lock().unwrap();
            Ok(seen.insert(*payment_hash))
        }
    }

    // ── Mock PricingEngine ─────────────────────────────────────────────

    struct MockPricing {
        price_msat: u64,
    }

    #[async_trait::async_trait]
    impl PricingEngine for MockPricing {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
            Ok(self.price_msat)
        }

        async fn get_category_price_msat(
            &self,
            _category: KindCategory,
        ) -> Result<u64, PricingError> {
            Ok(self.price_msat)
        }
    }

    // ── Mock LightningProvider ─────────────────────────────────────────

    struct MockLightning {
        settled: bool,
        amount_msat: u64,
        direction: PaymentDirection,
        preimage: Option<[u8; 32]>,
        payment_hash_override: Option<String>,
    }

    impl MockLightning {
        fn settled(amount_msat: u64) -> Self {
            Self {
                settled: true,
                amount_msat,
                direction: PaymentDirection::Incoming,
                preimage: Some([42u8; 32]),
                payment_hash_override: None,
            }
        }

        fn pending() -> Self {
            Self {
                settled: false,
                amount_msat: 0,
                direction: PaymentDirection::Incoming,
                preimage: None,
                payment_hash_override: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl LightningProvider for MockLightning {
        async fn create_invoice(
            &self,
            _amount_msat: u64,
            _description: &str,
            _expiry_secs: u32,
        ) -> Result<Invoice, LightningError> {
            Err(LightningError::InvoiceCreation(
                "mock: not supported".into(),
            ))
        }

        async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::PaymentFailed("mock: not supported".into()))
        }

        async fn get_payment_status(
            &self,
            payment_hash: &str,
        ) -> Result<PaymentDetails, LightningError> {
            let status = if self.settled {
                PaymentStatus::Settled
            } else {
                PaymentStatus::Pending
            };
            Ok(PaymentDetails {
                payment_hash: self
                    .payment_hash_override
                    .clone()
                    .unwrap_or_else(|| payment_hash.to_string()),
                preimage: self.preimage.map(hex::encode),
                amount_msat: self.amount_msat,
                status,
                direction: self.direction,
                timestamp: 0,
                memo: None,
                fee_msat: None,
            })
        }

        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    fn make_proof(amount_msat: u64) -> PaymentProof {
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        PaymentProof::new(hash, preimage, amount_msat)
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn make_signed_envelope(identity: &NodeIdentity, amount_msat: u64) -> UkmEnvelope {
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(amount_msat);
        let ciphertext = b"encrypted content".to_vec();

        let mut envelope = UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ciphertext, proof)
            .timestamp(now_ms())
            .build();

        // Sign the envelope
        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        envelope
    }

    /// Sign an envelope addressed to a SPECIFIC recipient node (the default
    /// `make_signed_envelope` hardcodes recipient = `Node([2u8; 32])`).
    fn make_signed_envelope_to(
        identity: &NodeIdentity,
        recipient: Recipient,
        amount_msat: u64,
    ) -> UkmEnvelope {
        let sender = *identity.node_id();
        let proof = make_proof(amount_msat);
        let ciphertext = b"encrypted content".to_vec();
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, ciphertext, proof)
                .timestamp(now_ms())
                .build();
        let sig = identity.sign(&envelope.signable_bytes());
        envelope.signature = crate::types::Signature::from_ed25519(&sig);
        envelope
    }

    // ── Tests ──────────────────────────────────────────────────────────

    /// M2 (the fix): a valid settlement proof for node B is NOT replayable as
    /// proof-of-payment for node A. B crafts a fully valid, signed, settled
    /// envelope addressed to ITSELF; an attacker presents it to A's gate. A
    /// supplies its OWN identity, and the settlement check must REJECT with
    /// `RecipientMismatch` even though payment_hash, direction==Incoming,
    /// amount>=required, and preimage all match.
    #[tokio::test]
    async fn settlement_proof_for_other_node_is_not_transferable() {
        let node_a = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
        let node_b = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();
        assert_ne!(node_a.node_id(), node_b.node_id(), "A and B must differ");

        let recipient_b = Recipient::Node(*node_b.node_id());
        let envelope_for_b = make_signed_envelope_to(&node_b, recipient_b, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        // Every PRE-EXISTING check passes; only recipient binding differs.
        let lightning = MockLightning::settled(100);

        let result = gate
            .verify_settlement(&envelope_for_b, &lightning, 100, Some(node_a.node_id()))
            .await;

        match result {
            Err(GateRejection::RecipientMismatch { claimed, ours }) => {
                assert_eq!(claimed, *node_b.node_id(), "claimed payee is B");
                assert_eq!(ours, *node_a.node_id(), "this node is A");
            }
            other => panic!(
                "a settlement proof addressed to B must be REJECTED as proof for A, got: {other:?}"
            ),
        }
    }

    /// Companion (does not over-reject): the same settled proof, presented to
    /// the correct payee (B binds with ITS OWN identity), still passes — the
    /// binding is additive and legitimate settlement is unbroken.
    #[tokio::test]
    async fn settlement_proof_for_correct_node_still_accepts() {
        let node_b = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();
        let recipient_b = Recipient::Node(*node_b.node_id());
        let envelope_for_b = make_signed_envelope_to(&node_b, recipient_b, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let lightning = MockLightning::settled(100);

        let result = gate
            .verify_settlement(&envelope_for_b, &lightning, 100, Some(node_b.node_id()))
            .await;

        assert!(
            result.is_ok(),
            "settlement for the correct payee must still pass: {result:?}"
        );
    }

    /// `None` identity means recipient binding is not requested for this call
    /// (e.g. the send path) — the other settlement checks still run, so a
    /// correctly-settled node-addressed proof is accepted (the binding is
    /// additive, only active when the receive path supplies an identity).
    #[tokio::test]
    async fn node_addressed_settlement_without_identity_skips_binding() {
        let node_b = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();
        let recipient_b = Recipient::Node(*node_b.node_id());
        let envelope = make_signed_envelope_to(&node_b, recipient_b, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let lightning = MockLightning::settled(100);

        let result = gate
            .verify_settlement(&envelope, &lightning, 100, None)
            .await;

        assert!(
            result.is_ok(),
            "with no identity the binding is skipped and the other checks pass: {result:?}"
        );
    }

    #[tokio::test]
    async fn accept_valid_message() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(result.is_ok(), "expected acceptance, got: {result:?}");
    }

    #[tokio::test]
    async fn reject_invalid_signature() {
        let alice = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
        let bob = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();

        // Create envelope from Alice but sign with Bob's key
        let sender = *alice.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(now_ms())
                .build();

        // Sign with Bob's key (wrong signer)
        let signable = envelope.signable_bytes();
        let sig = bob.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(matches!(result, Err(GateRejection::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn reject_replay_attack() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        // First attempt: accept
        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;
        assert!(result.is_ok());

        // Second attempt with same nonce: reject
        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;
        assert!(matches!(result, Err(GateRejection::ReplayDetected)));
    }

    #[tokio::test]
    async fn reject_non_whitelisted_sender() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        // Whitelist with a different node
        let mut whitelist = HashSet::new();
        whitelist.insert(NodeId::from_bytes([99u8; 32]));

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                Some(&whitelist),
                None,
                0.0,
                None,
            )
            .await;

        assert!(matches!(result, Err(GateRejection::NotWhitelisted(_))));
    }

    #[tokio::test]
    async fn accept_whitelisted_sender() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let mut whitelist = HashSet::new();
        whitelist.insert(*identity.node_id());

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                Some(&whitelist),
                None,
                0.0,
                None,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reject_insufficient_payment() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 5); // pays 5 msat

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 }; // requires 10 msat

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            }) => {
                assert_eq!(required_msat, 10);
                assert_eq!(paid_msat, 5);
            }
            other => panic!("expected InsufficientPayment, got: {other:?}"),
        }
    }

    /// Doctrine invariant: the whitelist is a FILTER, never an admission
    /// authority. A whitelisted sender that underpays must STILL be rejected —
    /// Step-2 membership must never short-circuit the price/settlement steps
    /// (Steps 5-7). The existing `accept_whitelisted_sender` overpays (100 for a
    /// 10-msat price), so it does not pin the "whitelisted-but-unpaid => reject"
    /// case; a future early-`Ok` on the Step-2 whitelist hit would silently make
    /// whitelist an admission authority and slip past every other gate test.
    /// This fails loudly if that regression ever lands.
    #[tokio::test]
    async fn whitelisted_sender_underpaying_is_still_rejected() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 5); // pays 5 msat

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 }; // requires 10 msat

        // Sender IS on the whitelist — Whitelist mode, membership satisfied.
        let mut whitelist = HashSet::new();
        whitelist.insert(*identity.node_id());

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                Some(&whitelist),
                None,
                0.0,
                None,
            )
            .await;

        // Membership must NOT bypass payment: the underpaying whitelisted sender
        // is rejected for InsufficientPayment — not admitted, and not
        // NotWhitelisted (it passed Step 2 and was caught at the price step).
        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            }) => {
                assert_eq!(required_msat, 10);
                assert_eq!(paid_msat, 5);
            }
            other => panic!(
                "whitelist must be a filter, not a bypass: a whitelisted underpaying \
                 sender must be rejected for InsufficientPayment, got: {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn reject_invalid_payment_proof() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));

        // Bad proof: preimage doesn't match hash
        let bad_proof = PaymentProof::new([0u8; 32], [1u8; 32], 100);

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), bad_proof)
                .timestamp(now_ms())
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(matches!(result, Err(GateRejection::InvalidEnvelope(_))));
    }

    #[tokio::test]
    async fn verify_lightning_settlement_success() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let config = GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        };
        let gate = PaymentGate::with_config(config);
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let lightning = MockLightning::settled(100);

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_lightning_settlement_failure() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let config = GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        };
        let gate = PaymentGate::with_config(config);
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let lightning = MockLightning::pending();

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        assert!(matches!(result, Err(GateRejection::PaymentNotSettled(_))));
    }

    #[tokio::test]
    async fn verify_lightning_settlement_rejects_amount_inflation() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let lightning = MockLightning::settled(10);

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::PaymentSettlementMismatch(_))
        ));
    }

    #[tokio::test]
    async fn verify_lightning_settlement_rejects_outgoing_payment() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let mut lightning = MockLightning::settled(100);
        lightning.direction = PaymentDirection::Outgoing;

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::PaymentSettlementMismatch(_))
        ));
    }

    #[tokio::test]
    async fn verify_lightning_settlement_rejects_preimage_mismatch() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let mut lightning = MockLightning::settled(100);
        lightning.preimage = Some([7u8; 32]);

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::PaymentSettlementMismatch(_))
        ));
    }

    #[tokio::test]
    async fn verify_lightning_settlement_rejects_payment_hash_reuse() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let first = make_signed_envelope(&identity, 100);
        let second = make_signed_envelope(&identity, 100);

        assert_ne!(
            first.nonce, second.nonce,
            "test needs a fresh envelope nonce"
        );
        assert_eq!(
            first.payment_proof.payment_hash,
            second.payment_proof.payment_hash
        );

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };
        let lightning = MockLightning::settled(100);

        assert!(
            gate.verify(&first, &nonce_store, &pricing, None, Some(&lightning), 0.0, None)
                .await
                .is_ok()
        );

        let result = gate
            .verify(&second, &nonce_store, &pricing, None, Some(&lightning), 0.0, None)
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::PaymentProofReused { .. })
        ));
    }

    #[tokio::test]
    async fn verify_rejects_payment_hash_reuse_without_settlement_check() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let first = make_signed_envelope(&identity, 100);
        let second = make_signed_envelope(&identity, 100);

        assert_ne!(
            first.nonce, second.nonce,
            "test needs a fresh envelope nonce"
        );
        assert_eq!(
            first.payment_proof.payment_hash,
            second.payment_proof.payment_hash
        );

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: false,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        assert!(
            gate.verify(&first, &nonce_store, &pricing, None, None, 0.0, None)
                .await
                .is_ok()
        );

        let result = gate
            .verify(&second, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::PaymentProofReused { .. })
        ));
    }

    #[tokio::test]
    async fn reject_when_lightning_required_but_missing() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let config = GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        };
        let gate = PaymentGate::with_config(config);
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(matches!(
            result,
            Err(GateRejection::LightningUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn accept_overpayment() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 1000); // pays 1000 msat

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 }; // only needs 10 msat

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(result.is_ok(), "overpayment should be accepted");
    }

    #[tokio::test]
    async fn reject_stale_message() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        // Timestamp 10 minutes in the past (default max is 5 min)
        let old_timestamp = now_ms() - 10 * 60 * 1000;
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"old data".to_vec(), proof)
                .timestamp(old_timestamp)
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        match result {
            Err(GateRejection::MessageTooOld { age_ms, max_ms }) => {
                assert!(age_ms >= 10 * 60 * 1000);
                assert_eq!(max_ms, 5 * 60 * 1000);
            }
            other => panic!("expected MessageTooOld, got: {other:?}"),
        }
    }

    // ── Boundary condition tests ────────────────────────────────────

    #[tokio::test]
    async fn accept_exact_payment() {
        // Payment exactly equals required price — should pass
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 10); // pays exactly 10

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 }; // requires exactly 10

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(result.is_ok(), "exact payment should be accepted");
    }

    #[tokio::test]
    async fn accept_zero_price_zero_payment() {
        // Both price and payment are 0 — free message
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 0);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 0 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "zero price with zero payment should be accepted"
        );
    }

    #[tokio::test]
    async fn reject_zero_payment_nonzero_price() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 0); // pays nothing

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 1 }; // requires 1 msat

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            }) => {
                assert_eq!(required_msat, 1);
                assert_eq!(paid_msat, 0);
            }
            other => panic!("expected InsufficientPayment, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_timestamp_at_epoch_zero() {
        // Timestamp = 0 is billions of ms old — should be rejected as too old
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"epoch zero".to_vec(), proof)
                .timestamp(0)
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::MessageTooOld { .. })),
            "epoch-0 timestamp should be rejected as too old"
        );
    }

    #[tokio::test]
    async fn reject_far_future_timestamp() {
        // A message timestamped 1 year in the future must be rejected.
        // Without this check, if nonces are ever pruned the message
        // becomes replayable.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let future_ts = now_ms() + 365 * 24 * 60 * 60 * 1000; // 1 year in the future
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"future".to_vec(), proof)
                .timestamp(future_ts)
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::MessageFromFuture { .. })),
            "far-future timestamp should be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn accept_slightly_future_timestamp() {
        // A message 1 minute in the future should be accepted (within
        // the 5-minute default tolerance for clock skew).
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let future_ts = now_ms() + 60 * 1000; // 1 minute ahead
        let mut envelope = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            sender,
            recipient,
            b"slight future".to_vec(),
            proof,
        )
        .timestamp(future_ts)
        .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "slightly-future timestamp should be accepted: {result:?}"
        );
    }

    struct FailingNonceStore;

    #[async_trait::async_trait]
    impl NonceStore for FailingNonceStore {
        async fn check_and_store(
            &self,
            _nonce: &Nonce,
            _sender: &NodeId,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Err("storage unavailable".into())
        }
    }

    /// A store that implements ONLY `check_and_store` and relies on the trait's
    /// default `check_and_store_payment_hash`. This models a backend that forgot
    /// to wire up economic replay protection.
    struct NoPaymentHashOverrideStore {
        seen: Mutex<HashSet<[u8; 24]>>,
    }

    #[async_trait::async_trait]
    impl NonceStore for NoPaymentHashOverrideStore {
        async fn check_and_store(
            &self,
            nonce: &Nonce,
            _sender: &NodeId,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.seen.lock().unwrap().insert(*nonce.as_bytes()))
        }
        // Deliberately does NOT override check_and_store_payment_hash.
    }

    #[tokio::test]
    async fn fail_closed_default_payment_hash_store_rejects() {
        // Money-path safety: the default `check_and_store_payment_hash` is
        // fail-closed. A NonceStore that forgets to override it must NOT silently
        // accept paid messages — the gate must reject (NonceCheckFailed) rather
        // than treat the unimplemented economic-replay check as a pass.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = NoPaymentHashOverrideStore {
            seen: Mutex::new(HashSet::new()),
        };
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::NonceCheckFailed(_))),
            "non-overriding payment-hash store must fail closed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn reject_when_nonce_store_fails() {
        // Fail-closed: nonce store error = rejection
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = FailingNonceStore;
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::NonceCheckFailed(_))),
            "nonce store failure should cause rejection, got: {result:?}"
        );
    }

    struct FailingPricing;

    #[async_trait::async_trait]
    impl PricingEngine for FailingPricing {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
            Err(PricingError::Other("pricing service down".into()))
        }

        async fn get_category_price_msat(
            &self,
            _category: KindCategory,
        ) -> Result<u64, PricingError> {
            Err(PricingError::Other("pricing service down".into()))
        }
    }

    #[tokio::test]
    async fn reject_when_pricing_engine_fails() {
        // Fail-closed: pricing engine error = rejection
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = FailingPricing;

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::PricingFailed(_))),
            "pricing failure should cause rejection, got: {result:?}"
        );
    }

    // ── PricingFailed error path with specific error context ──────────

    struct PricingFailedMock;

    #[async_trait::async_trait]
    impl PricingEngine for PricingFailedMock {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
            Err(PricingError::ChainUnavailable(
                "chain backend timeout after 30s".into(),
            ))
        }

        async fn get_category_price_msat(
            &self,
            _category: KindCategory,
        ) -> Result<u64, PricingError> {
            Err(PricingError::ChainUnavailable(
                "chain backend timeout after 30s".into(),
            ))
        }
    }

    #[tokio::test]
    async fn reject_when_pricing_returns_chain_unavailable() {
        // Fail-closed: when the pricing engine cannot determine price due to
        // chain unavailability, the gate must reject with PricingFailed.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 1_000_000); // generous payment

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = PricingFailedMock;

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        match &result {
            Err(GateRejection::PricingFailed(msg)) => {
                assert!(
                    msg.contains("chain backend timeout"),
                    "error message should propagate underlying cause, got: {msg}"
                );
            }
            other => panic!("expected PricingFailed with chain unavailable cause, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_whitelist_rejects_all() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        // Empty whitelist — no one is allowed
        let whitelist = HashSet::new();

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                Some(&whitelist),
                None,
                0.0,
                None,
            )
            .await;

        assert!(matches!(result, Err(GateRejection::NotWhitelisted(_))));
    }

    // ── NotPriceable kind tests ────────────────────────────────────

    struct NotPriceablePricing;

    #[async_trait::async_trait]
    impl PricingEngine for NotPriceablePricing {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError> {
            if (400..500).contains(&kind) || kind >= 600 {
                Err(PricingError::NotPriceable(kind))
            } else {
                Ok(10)
            }
        }

        async fn get_category_price_msat(
            &self,
            _category: KindCategory,
        ) -> Result<u64, PricingError> {
            Ok(10)
        }
    }

    #[tokio::test]
    async fn reject_not_priceable_kind_with_zero_payment() {
        // Pricing engines may still mark future/disabled kinds as NotPriceable.
        // Gate must reject them (fail-closed) — no free messages through the gate.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(0);

        let mut envelope = UkmEnvelopeBuilder::new(
            crate::kind::KIND_CALL_INVITE, // forced NotPriceable by the mock pricing engine
            sender,
            recipient,
            b"signaling data".to_vec(),
            proof,
        )
        .timestamp(now_ms())
        .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = NotPriceablePricing;

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::KindNotPriceable(400))),
            "NotPriceable kind must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn reject_not_priceable_kind_even_with_payment() {
        // Even with a payment attached, NotPriceable kinds must be rejected.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let mut envelope = UkmEnvelopeBuilder::new(
            crate::kind::KIND_CALL_ANSWER, // forced NotPriceable by the mock pricing engine
            sender,
            recipient,
            b"answer data".to_vec(),
            proof,
        )
        .timestamp(now_ms())
        .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = NotPriceablePricing;

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::KindNotPriceable(401))),
            "NotPriceable kind must be rejected even with payment: {result:?}"
        );
    }

    #[tokio::test]
    async fn reject_unknown_kind() {
        // Unknown kinds (outside all defined ranges) must also be rejected
        // through the same NotPriceable path.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        let mut envelope = UkmEnvelopeBuilder::new(
            60000, // unknown kind
            sender,
            recipient,
            b"unknown data".to_vec(),
            proof,
        )
        .timestamp(now_ms())
        .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = NotPriceablePricing;

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::KindNotPriceable(60000))),
            "Unknown kind must be rejected: {result:?}"
        );
    }

    // ── Max payment amount tests ─────────────────────────────────────

    #[tokio::test]
    async fn accept_max_u64_payment() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, u64::MAX);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing {
            price_msat: u64::MAX,
        };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "u64::MAX payment should be accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn reject_one_below_required_payment() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 99); // pays 99

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 100 }; // requires 100

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            }) => {
                assert_eq!(required_msat, 100);
                assert_eq!(paid_msat, 99);
            }
            other => panic!("expected InsufficientPayment, got: {other:?}"),
        }
    }

    // ── #218: settlement self-assertion vs. required-price invariant ──

    /// Council #218 invariant (money path): a settlement that is *internally
    /// consistent* — the Lightning backend reports a settled amount that meets
    /// the envelope's own self-asserted `amount_msat` — must STILL be rejected
    /// end-to-end when that self-asserted amount is below `required_msat`.
    ///
    /// In other words: a sender cannot lower the price by under-claiming. They
    /// set `payment_proof.amount_msat = 50` and genuinely settle 50 msat on
    /// Lightning (so `verify_settlement`'s `details.amount_msat >= envelope
    /// claim` check passes), but the kind costs 100 msat. The gate must reject.
    ///
    /// This drives the FULL gate (`verify`) with Lightning settlement
    /// verification ENABLED, so both `verify_price` (step 5) and
    /// `verify_settlement` (step 6) are live. The end-to-end rejection is
    /// `InsufficientPayment` from `verify_price`, which runs before settlement
    /// and is the structural enforcer of `required_msat`.
    #[tokio::test]
    async fn settlement_consistent_but_below_required_price_rejected_e2e() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Sender self-asserts (and genuinely settles) 50 msat...
        let envelope = make_signed_envelope(&identity, 50);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        // ...but the kind's required price is 100 msat.
        let pricing = MockPricing { price_msat: 100 };
        // Backend confirms a settled, incoming 50 msat payment. This is
        // INTERNALLY CONSISTENT with the envelope claim: settlement would
        // accept it in isolation (details.amount_msat == envelope claim).
        let lightning = MockLightning::settled(50);

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                None,
                Some(&lightning),
                0.0,
                None,
            )
            .await;

        // The gate must fail-closed on the price floor even though the
        // settlement is self-consistent.
        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat,
                paid_msat,
            }) => {
                assert_eq!(required_msat, 100, "required price must be the kind price");
                assert_eq!(paid_msat, 50, "paid must be the self-asserted claim");
            }
            other => panic!(
                "a self-consistent settlement below the required price must be \
                 rejected with InsufficientPayment, got: {other:?}"
            ),
        }
    }

    /// Council #218, the DEEPER fix (now CLOSED — was `#[ignore]`d as a gap).
    ///
    /// `verify_settlement` now takes `required_msat` and independently enforces
    /// the price floor: `details.amount_msat >= required_msat`. Previously the
    /// settlement layer only bound the settled amount to the envelope's
    /// *self-asserted* claim (`details.amount_msat >= envelope.payment_proof
    /// .amount_msat`), so if `verify_price` were ever removed, reordered after
    /// settlement, or bypassed, the settlement layer ALONE would happily accept
    /// a payment below the kind's required price.
    ///
    /// This test now drives `verify_settlement` in ISOLATION (not through the
    /// full `verify`, so `verify_price` does NOT run first) and asserts the
    /// settlement layer alone rejects a settled amount below `required_msat`
    /// with `InsufficientPayment`. Fail-closed at the settlement seam, not only
    /// at the pricing seam.
    #[tokio::test]
    async fn settlement_alone_binds_required_price() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Self-asserted claim == settled amount == 50, internally consistent
        // with the envelope claim (the old amount-consistency check passes).
        let envelope = make_signed_envelope(&identity, 50);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        // The required price for this kind is 100 msat — above the 50 settled.
        let required_msat: u64 = 100;
        let lightning = MockLightning::settled(50);

        // Call the settlement check in ISOLATION — `verify_price` does NOT run.
        // The settlement layer must now reject on the price floor by itself.
        let result = gate
            .verify_settlement(&envelope, &lightning, required_msat, None)
            .await;

        match result {
            Err(GateRejection::InsufficientPayment {
                required_msat: req,
                paid_msat,
            }) => {
                assert_eq!(req, 100, "settlement must enforce the required price");
                assert_eq!(paid_msat, 50, "paid must be the settled amount");
            }
            other => panic!(
                "settlement alone must reject a settled amount below the required \
                 price with InsufficientPayment, got: {other:?}"
            ),
        }
    }

    /// Companion to `settlement_alone_binds_required_price`: when the settled
    /// amount meets the required price, settlement alone accepts it. Pins that
    /// the new price-floor binding does not over-reject at/above the floor.
    #[tokio::test]
    async fn settlement_alone_accepts_at_required_price() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Claim == settled == 100, exactly the required price.
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::with_config(GateConfig {
            verify_lightning_settlement: true,
            ..Default::default()
        });
        let required_msat: u64 = 100;
        let lightning = MockLightning::settled(100);

        let result = gate
            .verify_settlement(&envelope, &lightning, required_msat, None)
            .await;

        assert!(
            result.is_ok(),
            "settlement at exactly the required price must be accepted: {result:?}"
        );
    }

    // ── Whitelist edge cases ─────────────────────────────────────────

    #[tokio::test]
    async fn no_whitelist_accepts_any_sender() {
        // whitelist=None means no whitelist check — any sender passes
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 100);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "None whitelist should accept any sender: {result:?}"
        );
    }

    // ── Multiple verification failures (ordering) ────────────────────

    #[tokio::test]
    async fn whitelist_check_before_signature_check() {
        // If sender is not whitelisted, the gate should reject before even
        // checking the signature. This matters for DoS resistance — signature
        // verification is CPU-expensive.
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        // Create envelope with INVALID signature (all zeros)
        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(now_ms())
                .build();
        // signature is default (all zeros) — invalid

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        // Whitelist that doesn't include the sender
        let whitelist = HashSet::new();

        let result = gate
            .verify(
                &envelope,
                &nonce_store,
                &pricing,
                Some(&whitelist),
                None,
                0.0,
                None,
            )
            .await;

        // Should be NotWhitelisted, NOT InvalidSignature
        assert!(
            matches!(result, Err(GateRejection::NotWhitelisted(_))),
            "whitelist check should happen before signature check, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn timestamp_check_before_signature_check() {
        // Stale message should be rejected before expensive signature verification
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        // Very old timestamp with invalid signature
        let envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"old".to_vec(), proof)
                .timestamp(1_000_000_000) // year ~2001 — very old
                .build();

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        // Should be MessageTooOld (timestamp checked before signature)
        assert!(
            matches!(result, Err(GateRejection::MessageTooOld { .. })),
            "timestamp check should happen before signature check, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn custom_max_age_config() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        // 2 minutes old — within default 5-min window, but outside 1-min custom window
        let ts = now_ms() - 2 * 60 * 1000;
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"data".to_vec(), proof)
                .timestamp(ts)
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let config = GateConfig {
            max_message_age_ms: 60 * 1000, // 1 minute
            ..Default::default()
        };
        let gate = PaymentGate::with_config(config);
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(result, Err(GateRejection::MessageTooOld { .. })),
            "2-min-old message should be rejected with 1-min max age"
        );
    }

    #[tokio::test]
    async fn accept_recent_message() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sender = *identity.node_id();
        let recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
        let proof = make_proof(100);

        // Timestamp 1 minute in the past (well within 5 min window)
        let recent_timestamp = now_ms() - 60 * 1000;
        let mut envelope =
            UkmEnvelopeBuilder::new(KIND_CHAT, sender, recipient, b"recent data".to_vec(), proof)
                .timestamp(recent_timestamp)
                .build();

        let signable = envelope.signable_bytes();
        let sig = identity.sign(&signable);
        envelope.signature = crate::types::Signature::from_ed25519(&sig);

        let gate = PaymentGate::new();
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "recent message should be accepted, got: {result:?}"
        );
    }

    // ── Cost floor (doorway hardening #4) ──────────────────────────────
    //
    // The resolved admission price is floored at `min_admission_cost_msat`,
    // the operator-modeled marginal cost of processing one inbound paid
    // contact. The floor defaults to 0 (off, no price change), can only ever
    // RAISE the required amount (fail-closed direction), and is applied after
    // the plasticity discount so a trusted peer's discount cannot undercut it.

    /// Floor at 0 (the default) is a pure no-op: a message that pays the base
    /// price is accepted exactly as before. Pins the non-regression guarantee.
    #[tokio::test]
    async fn cost_floor_zero_is_a_no_op() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 10);

        let gate = PaymentGate::with_config(GateConfig {
            min_admission_cost_msat: 0,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "floor=0 must not change behaviour, got: {result:?}"
        );
    }

    /// A payment that meets the base price but falls below the cost floor is
    /// rejected, and the rejection reports the *floored* required amount.
    #[tokio::test]
    async fn cost_floor_rejects_payment_below_cost() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Pays 10 — meets the base price, but the node's modeled cost is 50.
        let envelope = make_signed_envelope(&identity, 10);

        let gate = PaymentGate::with_config(GateConfig {
            min_admission_cost_msat: 50,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(
                result,
                Err(GateRejection::InsufficientPayment {
                    required_msat: 50,
                    paid_msat: 10,
                })
            ),
            "payment below the cost floor must be rejected at the floored \
             required amount, got: {result:?}"
        );
    }

    /// A payment exactly at the cost floor is accepted even though it exceeds
    /// the (lower) base price.
    #[tokio::test]
    async fn cost_floor_accepts_payment_at_the_floor() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 50);

        let gate = PaymentGate::with_config(GateConfig {
            min_admission_cost_msat: 50,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 10 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            result.is_ok(),
            "payment at the cost floor must be accepted, got: {result:?}"
        );
    }

    /// The cost floor is applied AFTER the plasticity trust discount, so even a
    /// maximally-trusted peer (50% discount) cannot pay below cost. base=100,
    /// discount=0.5 → discounted=50; floor=80 → required=80; paying the
    /// discounted 50 is rejected at 80.
    #[tokio::test]
    async fn cost_floor_cannot_be_undercut_by_trust_discount() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 50);

        let gate = PaymentGate::with_config(GateConfig {
            min_admission_cost_msat: 80,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 100 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.5, None)
            .await;

        assert!(
            matches!(
                result,
                Err(GateRejection::InsufficientPayment {
                    required_msat: 80,
                    paid_msat: 50,
                })
            ),
            "trust discount must not undercut the cost floor, got: {result:?}"
        );
    }

    /// A floor BELOW the resolved price never lowers it: base=100, floor=10,
    /// paying 50 is still rejected at the base 100 (the `.max()` is one-sided).
    #[tokio::test]
    async fn cost_floor_never_lowers_an_already_higher_price() {
        let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let envelope = make_signed_envelope(&identity, 50);

        let gate = PaymentGate::with_config(GateConfig {
            min_admission_cost_msat: 10,
            ..Default::default()
        });
        let nonce_store = MockNonceStore::new();
        let pricing = MockPricing { price_msat: 100 };

        let result = gate
            .verify(&envelope, &nonce_store, &pricing, None, None, 0.0, None)
            .await;

        assert!(
            matches!(
                result,
                Err(GateRejection::InsufficientPayment {
                    required_msat: 100,
                    paid_msat: 50,
                })
            ),
            "a floor below the base price must not lower required, got: {result:?}"
        );
    }
}
