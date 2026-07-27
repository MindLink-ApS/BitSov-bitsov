//! Mock Lightning provider — realistic behavior for testing.
//!
//! This provider operates entirely in-memory with no external dependencies.
//! It produces cryptographically valid payment proofs (SHA256(preimage) == hash)
//! and maintains a simulated balance.
//!
//! # Behavioral fidelity (matches real Lightning)
//!
//! - `create_invoice` returns `Pending` status (not auto-settled)
//! - `pay_invoice` returns the **original preimage** from the invoice
//!   (not a new random one) — this is how real Lightning works
//! - Insufficient balance causes `PaymentFailed`
//!
//! The preimage is embedded in the mock BOLT11 string so that
//! `pay_invoice` on a different mock instance can extract it.
//!
//! # When to use
//!
//! - Local testnet deployment (no LNbits infrastructure needed)
//! - Integration testing
//! - Development without Lightning backend
//!
//! The payment gate still enforces structure (signatures, nonces, whitelist,
//! preimage verification) — only the Lightning settlement is simulated.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, instrument};

use konsensus_core::traits::lightning::{
    InboundPayment, Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus,
};

/// Configuration for the mock provider.
#[derive(Debug, Clone)]
pub struct MockLightningConfig {
    /// Initial simulated balance in millisatoshis.
    pub initial_balance_msat: u64,
}

impl Default for MockLightningConfig {
    fn default() -> Self {
        Self {
            // 1 BTC in msat — generous testnet balance
            initial_balance_msat: 100_000_000_000,
        }
    }
}

/// A `(payment_hash, binding_tlv)` pair recorded by the mock's
/// `keysend_with_binding` send-half (test/inspection only).
type SentBinding = (String, Vec<u8>);

/// In-memory Lightning provider for testnet and development.
///
/// Invoices start as `Pending` until explicitly paid. Payment proofs are
/// cryptographically valid (the payment gate's preimage verification passes).
pub struct MockLightningProvider {
    /// Current simulated balance in millisatoshis.
    balance_msat: Arc<Mutex<u64>>,
    /// Stored invoices/payments by payment hash.
    payments: Arc<Mutex<HashMap<String, PaymentDetails>>>,
    /// Broadcast sender for settled INBOUND payments surfaced by
    /// `watch_inbound_keysend`. Test code drives it via `inject_inbound_keysend`.
    inbound_tx: broadcast::Sender<InboundPayment>,
    /// Record of `(payment_hash, binding_tlv)` pairs pushed via
    /// `keysend_with_binding`, so a test can assert the send-half threaded the
    /// ADR-037 binding verbatim. Test/inspection only.
    sent_bindings: Arc<Mutex<Vec<SentBinding>>>,
    /// Test knob: when `Some(n)`, the next `keysend` returns `InFlight` (carrying
    /// a payment hash but no preimage) instead of settling synchronously, and
    /// `get_payment_status` reports `InFlight` for `n` polls before flipping to
    /// `Settled`. Lets a test exercise the in-flight → settled poll path that
    /// real Lightning takes. `None` (default) = synchronous settle.
    keysend_defer_polls: Arc<Mutex<Option<u32>>>,
    /// Per-hash remaining `InFlight` polls for the deferred-settlement knob.
    pending_settle: Arc<Mutex<HashMap<String, u32>>>,
}

impl MockLightningProvider {
    /// Create a new mock provider with default config (1 BTC balance).
    pub fn new() -> Self {
        Self::with_config(MockLightningConfig::default())
    }

    /// Create a new mock provider with custom config.
    pub fn with_config(config: MockLightningConfig) -> Self {
        let (inbound_tx, _) = broadcast::channel(256);
        Self {
            balance_msat: Arc::new(Mutex::new(config.initial_balance_msat)),
            payments: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx,
            sent_bindings: Arc::new(Mutex::new(Vec::new())),
            keysend_defer_polls: Arc::new(Mutex::new(None)),
            pending_settle: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Test-only: arm the next [`LightningProvider::keysend`] to return
    /// `InFlight` and only report `Settled` after `polls`
    /// [`LightningProvider::get_payment_status`] calls — simulating a real HTLC
    /// that settles asynchronously a moment after dispatch.
    pub async fn defer_next_keysend_settlement(&self, polls: u32) {
        *self.keysend_defer_polls.lock().await = Some(polls);
    }

    /// Test/inspection-only: the `(payment_hash, binding_tlv)` pairs pushed via
    /// [`LightningProvider::keysend_with_binding`], in send order. Lets a test
    /// assert the send-half threaded the ADR-037 binding bytes verbatim onto the
    /// keysend without a real network.
    pub async fn sent_bindings(&self) -> Vec<SentBinding> {
        self.sent_bindings.lock().await.clone()
    }

    /// Generate a random preimage and its SHA256 hash.
    fn generate_proof() -> ([u8; 32], [u8; 32]) {
        use rand::RngCore;
        let mut preimage = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut preimage);
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        (preimage, hash)
    }

    /// Test/simulation-only: inject a settled, INBOUND keysend as if a
    /// counterparty pushed a spontaneous payment to us. Mirrors [`Self::keysend`]
    /// but flips `direction` to `Incoming`, records the settled record in the
    /// payments map so the gate's `get_payment_status` poll finds it, and emits it
    /// on the `watch_inbound_keysend` stream. Returns the `payment_hash` (hex).
    ///
    /// This is the keystone of the mock-first R2 proof: the mock is the only
    /// backend that can deterministically drive an unsolicited inbound keysend in
    /// a unit test, so it proves the receive→verify→admit wiring with no network.
    /// The preimage hashes to the returned `payment_hash` (a cryptographically
    /// valid proof the payment gate accepts).
    pub async fn inject_inbound_keysend(
        &self,
        amount_msat: u64,
        binding_tlv: Option<Vec<u8>>,
    ) -> String {
        let (preimage, hash) = Self::generate_proof();
        let payment_hash = hex::encode(hash);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let details = PaymentDetails {
            payment_hash: payment_hash.clone(),
            preimage: Some(hex::encode(preimage)),
            amount_msat,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Incoming,
            timestamp: now,
            memo: None,
            fee_msat: None,
        };
        // Poll-consistency: the gate's verify_settlement poll
        // (`get_payment_status`) must find this exact settled record.
        self.payments
            .lock()
            .await
            .insert(payment_hash.clone(), details.clone());
        // Emit on the inbound stream. A send error only means no subscriber is
        // currently listening; the record is still persisted for the poll path.
        let _ = self.inbound_tx.send(InboundPayment {
            details,
            binding_tlv,
        });
        payment_hash
    }

    /// Encode a mock BOLT11 string that carries the preimage for cross-instance pay.
    ///
    /// Format: `lnbcrt{amount_sats}m1mock{hash_prefix}p{preimage_hex}`
    ///
    /// This allows `pay_invoice` on a **different** mock instance to extract the
    /// original preimage — matching real Lightning behavior where the preimage
    /// is revealed by the invoice creator upon settlement.
    fn encode_bolt11(amount_msat: u64, hash: &[u8; 32], preimage: &[u8; 32]) -> String {
        format!(
            "lnbcrt{}m1mock{}p{}",
            amount_msat / 1000,
            &hex::encode(hash)[..16],
            hex::encode(preimage),
        )
    }

    /// Extract the preimage and amount from a mock BOLT11 string.
    ///
    /// Returns `(preimage_hex, amount_msat)` or `None` if the format is unrecognized.
    fn decode_bolt11(bolt11: &str) -> Option<(String, u64)> {
        let stripped = bolt11.strip_prefix("lnbcrt")?;
        let (amount_str, rest) = stripped.split_once('m')?;
        let amount_sats: u64 = amount_str.parse().ok()?;

        // New format with embedded preimage: ...p{preimage_hex}
        if let Some((_prefix, preimage_hex)) = rest.split_once('p') {
            if preimage_hex.len() == 64 {
                return Some((preimage_hex.to_string(), amount_sats * 1000));
            }
        }

        // Legacy format without preimage (backward compat)
        None
    }

    /// Settle an invoice (called internally when `pay_invoice` targets a local invoice).
    ///
    /// Updates the payment status from `Pending` to `Settled`, sets the preimage,
    /// and credits the balance.
    async fn settle_local_invoice(&self, payment_hash: &str, preimage: &str) {
        let mut payments = self.payments.lock().await;
        if let Some(details) = payments.get_mut(payment_hash) {
            if details.status == PaymentStatus::Pending {
                details.status = PaymentStatus::Settled;
                details.preimage = Some(preimage.to_string());
                let amount = details.amount_msat;
                drop(payments);
                *self.balance_msat.lock().await += amount;
            }
        }
    }
}

impl Default for MockLightningProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LightningProvider for MockLightningProvider {
    #[instrument(skip(self), fields(amount_msat, description))]
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let (preimage, hash) = Self::generate_proof();
        let payment_hash = hex::encode(hash);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Invoice starts as Pending — not settled until paid.
        // Preimage is NOT exposed in PaymentDetails (only the invoice creator
        // knows it, and it's revealed upon settlement).
        let details = PaymentDetails {
            payment_hash: payment_hash.clone(),
            preimage: None,
            amount_msat,
            status: PaymentStatus::Pending,
            direction: PaymentDirection::Incoming,
            timestamp: now,
            memo: Some(description.to_string()),
            fee_msat: None,
        };

        self.payments
            .lock()
            .await
            .insert(payment_hash.clone(), details);

        // Balance is NOT credited yet — only credited when settled.

        // Encode preimage in BOLT11 so pay_invoice can extract it
        let bolt11 = Self::encode_bolt11(amount_msat, &hash, &preimage);

        debug!(payment_hash = %payment_hash, amount_msat, "mock invoice created (pending)");

        Ok(Invoice {
            bolt11,
            payment_hash,
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: now,
        })
    }

    #[instrument(skip(self, bolt11))]
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Extract preimage and amount from the mock BOLT11 string.
        // In real Lightning, the preimage is revealed by the recipient upon
        // HTLC settlement — here we simulate this by embedding it in BOLT11.
        let (preimage_hex, amount_msat) = Self::decode_bolt11(bolt11).unwrap_or_else(|| {
            // Fallback for unrecognized formats: generate a new proof
            // (legacy behavior, used for malformed or non-mock invoices)
            let (preimage, hash) = Self::generate_proof();
            let _ = hash; // Not used in fallback
            (hex::encode(preimage), 1000)
        });

        // Compute the payment hash from the preimage
        let preimage_bytes = hex::decode(&preimage_hex).map_err(|e| {
            LightningError::PaymentFailed(format!("invalid preimage in bolt11: {e}"))
        })?;
        let hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
        let payment_hash = hex::encode(hash);

        // Debit balance
        let mut balance = self.balance_msat.lock().await;
        if *balance < amount_msat {
            return Err(LightningError::PaymentFailed(
                "insufficient mock balance".into(),
            ));
        }
        *balance -= amount_msat;
        drop(balance);

        // If this invoice exists locally (self-pay scenario), settle it
        self.settle_local_invoice(&payment_hash, &preimage_hex).await;

        let details = PaymentDetails {
            payment_hash: payment_hash.clone(),
            preimage: Some(preimage_hex),
            amount_msat,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: None,
            fee_msat: None,
        };

        self.payments
            .lock()
            .await
            .insert(format!("out-{payment_hash}"), details.clone());

        debug!(payment_hash = %payment_hash, amount_msat, "mock payment settled");

        Ok(details)
    }

    #[instrument(skip(self))]
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        // Deferred-settlement test knob: report InFlight (masking the preimage)
        // until the per-hash poll counter drains, then fall through to the
        // stored Settled record.
        {
            let mut pending = self.pending_settle.lock().await;
            if let Some(remaining) = pending.get_mut(payment_hash) {
                if *remaining > 0 {
                    *remaining -= 1;
                    let mut d = self
                        .payments
                        .lock()
                        .await
                        .get(payment_hash)
                        .cloned()
                        .ok_or_else(|| LightningError::PaymentNotFound(payment_hash.to_string()))?;
                    d.status = PaymentStatus::InFlight;
                    d.preimage = None;
                    return Ok(d);
                }
                pending.remove(payment_hash);
            }
        }
        self.payments
            .lock()
            .await
            .get(payment_hash)
            .cloned()
            .ok_or_else(|| LightningError::PaymentNotFound(payment_hash.to_string()))
    }

    #[instrument(skip(self))]
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(*self.balance_msat.lock().await)
    }

    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let payments = self.payments.lock().await;
        let mut list: Vec<PaymentDetails> = payments.values().cloned().collect();
        // Sort by timestamp descending (most recent first)
        list.sort_by_key(|p| std::cmp::Reverse(p.timestamp));
        list.truncate(limit as usize);
        Ok(list)
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn watch_inbound_keysend(
        &self,
    ) -> Result<BoxStream<'static, InboundPayment>, LightningError> {
        let rx = self.inbound_tx.subscribe();
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(item) => return Some((item, rx)),
                    // A lagged consumer skips missed items rather than ending the
                    // stream. (The LDK backend's authoritative admission path will
                    // use mpsc backpressure so a settled payment is never dropped;
                    // the mock keeps the stream alive for test ergonomics.)
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(stream.boxed())
    }

    #[instrument(skip(self))]
    async fn keysend(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Validate destination pubkey format (66 hex chars for compressed pubkey)
        if dest_pubkey.len() != 66 || hex::decode(dest_pubkey).is_err() {
            return Err(LightningError::PaymentFailed(
                "invalid destination pubkey".into(),
            ));
        }

        // Sender generates preimage and pushes it with the payment
        let (preimage, hash) = Self::generate_proof();
        let preimage_hex = hex::encode(preimage);
        let payment_hash = hex::encode(hash);

        // Debit balance
        let mut balance = self.balance_msat.lock().await;
        if *balance < amount_msat {
            return Err(LightningError::PaymentFailed(
                "insufficient mock balance".into(),
            ));
        }
        *balance -= amount_msat;
        drop(balance);

        let details = PaymentDetails {
            payment_hash: payment_hash.clone(),
            preimage: Some(preimage_hex),
            amount_msat,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: now,
            memo: memo.map(String::from),
            fee_msat: None,
        };

        // Test knob: optionally return in-flight and only settle on later polls,
        // keyed by the raw hash so `get_payment_status` can find and settle it.
        if let Some(n) = self.keysend_defer_polls.lock().await.take() {
            self.payments
                .lock()
                .await
                .insert(payment_hash.clone(), details.clone());
            self.pending_settle.lock().await.insert(payment_hash.clone(), n);
            debug!(payment_hash = %payment_hash, polls = n, "mock keysend in-flight (deferred settle)");
            return Ok(PaymentDetails {
                status: PaymentStatus::InFlight,
                preimage: None,
                ..details
            });
        }

        self.payments
            .lock()
            .await
            .insert(format!("keysend-{payment_hash}"), details.clone());

        debug!(
            payment_hash = %payment_hash,
            dest = %dest_pubkey,
            amount_msat,
            "mock keysend settled"
        );

        Ok(details)
    }

    #[instrument(skip(self, binding_tlv))]
    async fn keysend_with_binding(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        binding_tlv: &[u8],
    ) -> Result<PaymentDetails, LightningError> {
        if binding_tlv.is_empty() {
            return Err(LightningError::Backend(
                "binding-TLV keysend requires a non-empty binding".into(),
            ));
        }

        // Reuse the bare-keysend settlement path (balance debit, proof, record).
        let details = self.keysend(dest_pubkey, amount_msat, None).await?;

        // Record the ADR-037 binding the send-half threaded onto this keysend so
        // a test can assert it round-trips verbatim. The mock models a single
        // node, so this does NOT loop back to our own `watch_inbound_keysend`
        // (that would conflate send and receive on one node); the true on-wire
        // join is exercised by the LDK regtest round-trip test.
        self.sent_bindings
            .lock()
            .await
            .push((details.payment_hash.clone(), binding_tlv.to_vec()));

        debug!(
            payment_hash = %details.payment_hash,
            dest = %dest_pubkey,
            amount_msat,
            binding_len = binding_tlv.len(),
            "mock keysend_with_binding settled"
        );

        Ok(details)
    }

    #[instrument(skip(self))]
    async fn create_hodl_invoice(
        &self,
        payment_hash: &str,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        // Validate the payment hash format
        if payment_hash.len() != 64 || hex::decode(payment_hash).is_err() {
            return Err(LightningError::InvoiceCreation(
                "invalid payment hash (expected 64 hex chars)".into(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // HODL invoice: Pending until settle_hodl_invoice or cancel_hodl_invoice
        let details = PaymentDetails {
            payment_hash: payment_hash.to_string(),
            preimage: None,
            amount_msat,
            status: PaymentStatus::Pending,
            direction: PaymentDirection::Incoming,
            timestamp: now,
            memo: Some(description.to_string()),
            fee_msat: None,
        };

        self.payments
            .lock()
            .await
            .insert(format!("hodl-{payment_hash}"), details);

        let bolt11 = format!("lnbcrt{}m1hodl{}", amount_msat / 1000, &payment_hash[..32]);

        debug!(
            payment_hash = %payment_hash,
            amount_msat,
            "mock HODL invoice created (pending)"
        );

        Ok(Invoice {
            bolt11,
            payment_hash: payment_hash.to_string(),
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: now,
        })
    }

    #[instrument(skip(self))]
    async fn settle_hodl_invoice(&self, preimage: &str) -> Result<(), LightningError> {
        // Validate and compute payment hash
        let preimage_bytes = hex::decode(preimage).map_err(|e| {
            LightningError::PaymentFailed(format!("invalid preimage hex: {e}"))
        })?;
        if preimage_bytes.len() != 32 {
            return Err(LightningError::PaymentFailed(
                "preimage must be 32 bytes".into(),
            ));
        }
        let hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
        let payment_hash = hex::encode(hash);
        let hodl_key = format!("hodl-{payment_hash}");

        let mut payments = self.payments.lock().await;
        let details = payments.get_mut(&hodl_key).ok_or_else(|| {
            LightningError::PaymentNotFound(format!("no HODL invoice for hash {payment_hash}"))
        })?;

        if details.status != PaymentStatus::Pending {
            return Err(LightningError::PaymentFailed(format!(
                "HODL invoice not pending, status: {:?}",
                details.status
            )));
        }

        let amount = details.amount_msat;
        details.status = PaymentStatus::Settled;
        details.preimage = Some(preimage.to_string());
        drop(payments);

        // Credit balance on settlement
        *self.balance_msat.lock().await += amount;

        debug!(payment_hash = %payment_hash, "mock HODL invoice settled");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn cancel_hodl_invoice(&self, payment_hash: &str) -> Result<(), LightningError> {
        let hodl_key = format!("hodl-{payment_hash}");

        let mut payments = self.payments.lock().await;
        let details = payments.get_mut(&hodl_key).ok_or_else(|| {
            LightningError::PaymentNotFound(format!("no HODL invoice for hash {payment_hash}"))
        })?;

        if details.status != PaymentStatus::Pending {
            return Err(LightningError::PaymentFailed(format!(
                "HODL invoice not pending, status: {:?}",
                details.status
            )));
        }

        details.status = PaymentStatus::Failed;

        debug!(payment_hash = %payment_hash, "mock HODL invoice cancelled");
        Ok(())
    }

    async fn get_node_pubkey(&self) -> Option<String> {
        // Return a deterministic mock pubkey for testing keysend flows.
        Some("02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into())
    }

    async fn close_channel(
        &self,
        _channel_id: &str,
        _force: bool,
    ) -> Result<Option<String>, LightningError> {
        Err(LightningError::Backend("close_channel is LDK-only".into()))
    }
}

#[cfg(test)]
#[path = "tests/mock.rs"]
mod tests;
