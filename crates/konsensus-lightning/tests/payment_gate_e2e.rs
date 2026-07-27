//! B8: Payment gate end-to-end verification using MockLightningProvider.
//!
//! This test runs without external infrastructure and verifies the complete
//! payment flow that the payment gate relies on:
//!
//! 1. Two independent provider instances (simulating two nodes)
//! 2. Recipient creates invoice
//! 3. Sender pays invoice (cross-instance, extracting preimage from bolt11)
//! 4. Payment proof is cryptographically valid: SHA256(preimage) == payment_hash
//! 5. Balance accounting is correct
//! 6. Self-pay scenario exercises verify_payment() end-to-end
//!
//! This test always runs during `cargo test --workspace`.

use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};
use konsensus_lightning::MockLightningProvider;
use sha2::{Digest, Sha256};

/// Two-node payment flow with cryptographic proof verification.
#[tokio::test]
async fn mock_cross_instance_payment_proof() {
    // Two independent mock providers = two simulated nodes
    let sender = MockLightningProvider::new();
    let recipient = MockLightningProvider::new();

    let balance_before = sender.get_balance_msat().await.unwrap();

    // ── Recipient creates invoice ────────────────────────────────────────
    let amount_msat: u64 = 250_000; // 250 sats
    let invoice = recipient
        .create_invoice(amount_msat, "gate verification test", 3600)
        .await
        .expect("invoice creation should succeed");

    assert_eq!(invoice.amount_msat, amount_msat);
    assert!(!invoice.payment_hash.is_empty());
    assert!(!invoice.bolt11.is_empty());

    // Invoice should be pending on recipient
    let status = recipient
        .get_payment_status(&invoice.payment_hash)
        .await
        .unwrap();
    assert_eq!(status.status, PaymentStatus::Pending);
    assert_eq!(status.direction, PaymentDirection::Incoming);

    // ── Sender pays the invoice (cross-instance) ────────────────────────
    let payment = sender
        .pay_invoice(&invoice.bolt11)
        .await
        .expect("payment should succeed");

    assert_eq!(payment.direction, PaymentDirection::Outgoing);
    assert_eq!(payment.status, PaymentStatus::Settled);
    assert_eq!(payment.amount_msat, amount_msat);
    assert!(payment.preimage.is_some(), "settled payment must have preimage");

    // ── Cryptographic proof: SHA256(preimage) == payment_hash ────────────
    // This is the fundamental invariant the payment gate checks.
    let preimage_hex = payment.preimage.unwrap();
    let preimage_bytes = hex::decode(&preimage_hex).expect("preimage should be valid hex");
    assert_eq!(preimage_bytes.len(), 32, "preimage should be 32 bytes");

    let computed_hash = Sha256::digest(&preimage_bytes);
    assert_eq!(
        hex::encode(computed_hash),
        invoice.payment_hash,
        "SHA256(preimage) must equal payment_hash"
    );

    // ── Balance accounting ───────────────────────────────────────────────
    let balance_after = sender.get_balance_msat().await.unwrap();
    assert_eq!(
        balance_after,
        balance_before - amount_msat,
        "Sender balance should decrease by payment amount"
    );
}

/// Self-pay exercises the full verify_payment() path end-to-end.
/// When a node creates and pays its own invoice, the incoming payment
/// is settled and verify_payment() succeeds — proving the gate's
/// Lightning settlement verification works.
#[tokio::test]
async fn mock_self_pay_verify_payment() {
    let node = MockLightningProvider::new();

    let amount_msat: u64 = 500_000;
    let invoice = node
        .create_invoice(amount_msat, "self-pay gate test", 3600)
        .await
        .unwrap();

    // Pay own invoice — settles the incoming payment
    let payment = node.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(payment.status, PaymentStatus::Settled);

    // verify_payment() is the method PaymentGate uses when
    // verify_lightning_settlement is enabled
    let verification = node
        .verify_payment(&invoice.payment_hash)
        .await
        .expect("verify_payment should succeed for self-payment");
    assert_eq!(verification.status, PaymentStatus::Settled);
    assert!(verification.preimage.is_some());

    // Cryptographic proof
    let preimage_hex = verification.preimage.unwrap();
    let preimage_bytes = hex::decode(&preimage_hex).unwrap();
    let computed_hash = Sha256::digest(&preimage_bytes);
    assert_eq!(hex::encode(computed_hash), invoice.payment_hash);
}

/// verify_payment must reject unsettled payments (fail-closed).
#[tokio::test]
async fn mock_verify_payment_rejects_pending() {
    let node = MockLightningProvider::new();

    // Create invoice but don't pay it
    let invoice = node
        .create_invoice(100_000, "unpaid invoice", 3600)
        .await
        .unwrap();

    // verify_payment must fail — the gate is fail-closed
    let result = node.verify_payment(&invoice.payment_hash).await;
    assert!(
        result.is_err(),
        "verify_payment must reject unsettled payments (fail-closed)"
    );
}

/// verify_payment must reject unknown payment hashes.
#[tokio::test]
async fn mock_verify_payment_rejects_unknown_hash() {
    let node = MockLightningProvider::new();

    let fake_hash = "a".repeat(64);
    let result = node.verify_payment(&fake_hash).await;
    assert!(
        result.is_err(),
        "verify_payment must reject unknown payment hashes"
    );
}

/// Multiple sequential payments — verifies each payment produces an
/// independently valid cryptographic proof (as happens in messaging flows).
#[tokio::test]
async fn mock_sequential_payments_proof_verification() {
    let sender = MockLightningProvider::new();
    let recipient = MockLightningProvider::new();

    let amounts = [10_000u64, 25_000, 50_000, 100_000, 1_000];

    for (i, &amount) in amounts.iter().enumerate() {
        let invoice = recipient
            .create_invoice(amount, &format!("message {i}"), 3600)
            .await
            .unwrap();

        let payment = sender.pay_invoice(&invoice.bolt11).await.unwrap();
        assert_eq!(payment.status, PaymentStatus::Settled);
        assert!(payment.preimage.is_some());

        // Each payment must produce a valid cryptographic proof
        let preimage_bytes = hex::decode(payment.preimage.unwrap()).unwrap();
        let hash = Sha256::digest(&preimage_bytes);
        assert_eq!(
            hex::encode(hash),
            invoice.payment_hash,
            "Payment {i}: SHA256(preimage) must equal payment_hash"
        );
    }

    // Verify total balance deducted
    let total_paid: u64 = amounts.iter().sum();
    let balance = sender.get_balance_msat().await.unwrap();
    assert_eq!(
        balance,
        100_000_000_000 - total_paid,
        "Balance should reflect all payments"
    );
}

/// Insufficient balance must be rejected (payment gate fail-closed).
#[tokio::test]
async fn mock_insufficient_balance_rejected() {
    use konsensus_lightning::MockLightningConfig;

    // Create a provider with very low balance
    let sender = MockLightningProvider::with_config(MockLightningConfig {
        initial_balance_msat: 1_000,
    });
    let recipient = MockLightningProvider::new();

    let invoice = recipient
        .create_invoice(10_000, "too expensive", 3600)
        .await
        .unwrap();

    let result = sender.pay_invoice(&invoice.bolt11).await;
    assert!(
        result.is_err(),
        "Payment must fail when balance is insufficient"
    );
}
