use super::*;

#[tokio::test]
async fn create_invoice_starts_pending() {
    let provider = MockLightningProvider::new();
    let invoice = provider
        .create_invoice(10_000, "test", 3600)
        .await
        .unwrap();

    assert!(!invoice.payment_hash.is_empty());
    assert!(!invoice.bolt11.is_empty());
    assert_eq!(invoice.amount_msat, 10_000);

    // Should be pending (not auto-settled)
    let status = provider
        .get_payment_status(&invoice.payment_hash)
        .await
        .unwrap();
    assert_eq!(status.status, PaymentStatus::Pending);
    // Preimage NOT exposed until settlement
    assert!(status.preimage.is_none());
}

#[tokio::test]
async fn pay_invoice_returns_original_preimage() {
    // Simulate two separate nodes: recipient creates invoice, sender pays
    let recipient = MockLightningProvider::new();
    let sender = MockLightningProvider::new();

    let invoice = recipient
        .create_invoice(5_000, "cross-instance test", 3600)
        .await
        .unwrap();

    // Sender pays the invoice
    let payment = sender.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(payment.status, PaymentStatus::Settled);

    // The preimage returned by pay_invoice must be the ORIGINAL one
    // that hashes to the invoice's payment_hash
    let preimage_bytes = hex::decode(payment.preimage.as_ref().unwrap()).unwrap();
    let expected_hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    let actual_hash = hex::decode(&invoice.payment_hash).unwrap();
    assert_eq!(
        expected_hash.as_slice(),
        actual_hash.as_slice(),
        "pay_invoice must return the preimage that hashes to the invoice's payment_hash"
    );
}

#[tokio::test]
async fn self_pay_settles_invoice() {
    let provider = MockLightningProvider::new();
    let initial_balance = provider.get_balance_msat().await.unwrap();

    let invoice = provider
        .create_invoice(10_000, "self-pay", 3600)
        .await
        .unwrap();

    // Balance should NOT change on create_invoice (Pending)
    let balance_after_create = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance_after_create, initial_balance);

    // Pay the invoice (self-pay)
    let payment = provider.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(payment.status, PaymentStatus::Settled);

    // Invoice should now be settled
    let status = provider
        .get_payment_status(&invoice.payment_hash)
        .await
        .unwrap();
    assert_eq!(status.status, PaymentStatus::Settled);
    assert!(status.preimage.is_some());

    // Net balance effect: -10K (outgoing) + 10K (incoming settled) = 0
    let balance_after_pay = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance_after_pay, initial_balance);
}

#[tokio::test]
async fn pay_invoice_deducts_balance() {
    let config = MockLightningConfig {
        initial_balance_msat: 100_000,
    };
    let provider = MockLightningProvider::with_config(config);

    let balance_before = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance_before, 100_000);

    // Create invoice on a separate "recipient"
    let recipient = MockLightningProvider::new();
    let invoice = recipient
        .create_invoice(10_000, "test", 3600)
        .await
        .unwrap();

    // Pay the invoice
    let details = provider.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
    assert_eq!(details.amount_msat, 10_000);

    let balance_after = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance_after, 90_000);
}

#[tokio::test]
async fn pay_invoice_insufficient_balance() {
    let config = MockLightningConfig {
        initial_balance_msat: 500,
    };
    let provider = MockLightningProvider::with_config(config);

    let recipient = MockLightningProvider::new();
    let invoice = recipient
        .create_invoice(10_000, "too expensive", 3600)
        .await
        .unwrap();

    let result = provider.pay_invoice(&invoice.bolt11).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("insufficient mock balance"));
}

#[tokio::test]
async fn create_invoice_does_not_credit_balance() {
    let config = MockLightningConfig {
        initial_balance_msat: 50_000,
    };
    let provider = MockLightningProvider::with_config(config);

    provider
        .create_invoice(25_000, "incoming", 3600)
        .await
        .unwrap();

    // Balance should NOT change (invoice is Pending)
    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, 50_000);
}

#[tokio::test]
async fn is_always_available() {
    let provider = MockLightningProvider::new();
    assert!(provider.is_available().await);
}

#[tokio::test]
async fn payment_not_found() {
    let provider = MockLightningProvider::new();
    let result = provider.get_payment_status("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_payment_settled_invoice() {
    let provider = MockLightningProvider::new();
    let invoice = provider
        .create_invoice(1_000, "verify test", 3600)
        .await
        .unwrap();

    // Invoice is Pending — verify_payment should fail (not settled)
    let result = provider.verify_payment(&invoice.payment_hash).await;
    assert!(result.is_err(), "verify_payment should fail for Pending invoices");

    // Self-pay to settle
    provider.pay_invoice(&invoice.bolt11).await.unwrap();

    // Now verify_payment should succeed
    let details = provider
        .verify_payment(&invoice.payment_hash)
        .await
        .unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
}

#[tokio::test]
async fn payment_proof_is_cryptographically_valid() {
    let provider = MockLightningProvider::new();
    let invoice = provider
        .create_invoice(5_000, "proof test", 3600)
        .await
        .unwrap();

    // Pay the invoice so it settles and preimage is available
    provider.pay_invoice(&invoice.bolt11).await.unwrap();

    let status = provider
        .get_payment_status(&invoice.payment_hash)
        .await
        .unwrap();

    // Verify SHA256(preimage) == payment_hash
    let preimage_bytes = hex::decode(status.preimage.unwrap()).unwrap();
    let expected_hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    let actual_hash = hex::decode(&invoice.payment_hash).unwrap();
    assert_eq!(expected_hash.as_slice(), actual_hash.as_slice());
}

// ── Keysend tests ──────────────────────────────────────────────────

#[tokio::test]
async fn keysend_deducts_balance_and_returns_proof() {
    let config = MockLightningConfig {
        initial_balance_msat: 100_000,
    };
    let provider = MockLightningProvider::with_config(config);

    // Valid compressed pubkey (33 bytes = 66 hex chars)
    let dest = "02" .to_string() + &"ab".repeat(32);
    let payment = provider.keysend(&dest, 5_000, Some("tip")).await.unwrap();

    assert_eq!(payment.status, PaymentStatus::Settled);
    assert_eq!(payment.amount_msat, 5_000);
    assert!(payment.preimage.is_some());
    assert_eq!(payment.memo.as_deref(), Some("tip"));

    // Verify preimage is cryptographically valid
    let preimage_bytes = hex::decode(payment.preimage.unwrap()).unwrap();
    let hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    assert_eq!(hex::encode(hash), payment.payment_hash);

    // Balance should be debited
    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, 95_000);
}

#[tokio::test]
async fn keysend_insufficient_balance() {
    let config = MockLightningConfig {
        initial_balance_msat: 1_000,
    };
    let provider = MockLightningProvider::with_config(config);
    let dest = "02".to_string() + &"cd".repeat(32);

    let result = provider.keysend(&dest, 5_000, None).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("insufficient"));
}

#[tokio::test]
async fn keysend_invalid_pubkey() {
    let provider = MockLightningProvider::new();
    let result = provider.keysend("not-a-pubkey", 1_000, None).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid destination pubkey"));
}

// ── HODL invoice tests ───────────────────────────────────────────────

#[tokio::test]
async fn hodl_invoice_settle_flow() {
    let provider = MockLightningProvider::new();
    let initial_balance = provider.get_balance_msat().await.unwrap();

    // Generate a preimage and compute its hash
    let preimage = [42u8; 32];
    let preimage_hex = hex::encode(preimage);
    let hash: [u8; 32] = Sha256::digest(&preimage).into();
    let payment_hash = hex::encode(hash);

    // Create HODL invoice
    let invoice = provider
        .create_hodl_invoice(&payment_hash, 10_000, "escrow", 3600)
        .await
        .unwrap();
    assert_eq!(invoice.payment_hash, payment_hash);
    assert_eq!(invoice.amount_msat, 10_000);

    // Balance should NOT change yet
    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, initial_balance);

    // Settle with the preimage
    provider.settle_hodl_invoice(&preimage_hex).await.unwrap();

    // Balance should be credited now
    let balance = provider.get_balance_msat().await.unwrap();
    assert_eq!(balance, initial_balance + 10_000);
}

#[tokio::test]
async fn hodl_invoice_cancel_flow() {
    let provider = MockLightningProvider::new();

    let preimage = [99u8; 32];
    let hash: [u8; 32] = Sha256::digest(&preimage).into();
    let payment_hash = hex::encode(hash);

    provider
        .create_hodl_invoice(&payment_hash, 5_000, "cancel test", 3600)
        .await
        .unwrap();

    // Cancel the HODL invoice
    provider.cancel_hodl_invoice(&payment_hash).await.unwrap();

    // Cannot settle after cancel
    let result = provider.settle_hodl_invoice(&hex::encode(preimage)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not pending"));
}

#[tokio::test]
async fn hodl_invoice_invalid_payment_hash() {
    let provider = MockLightningProvider::new();
    let result = provider
        .create_hodl_invoice("not-a-hash", 5_000, "bad", 3600)
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid payment hash"));
}

#[tokio::test]
async fn hodl_settle_wrong_preimage() {
    let provider = MockLightningProvider::new();

    let preimage = [1u8; 32];
    let hash: [u8; 32] = Sha256::digest(&preimage).into();
    let payment_hash = hex::encode(hash);

    provider
        .create_hodl_invoice(&payment_hash, 5_000, "test", 3600)
        .await
        .unwrap();

    // Try to settle with a different preimage (its hash won't match)
    let wrong_preimage = hex::encode([2u8; 32]);
    let result = provider.settle_hodl_invoice(&wrong_preimage).await;
    // Should fail because the wrong preimage's hash doesn't match any HODL invoice
    assert!(result.is_err());
}

#[tokio::test]
async fn list_payments_returns_all() {
    let provider = MockLightningProvider::new();
    let recipient = MockLightningProvider::new();

    // Create and pay 3 invoices
    for i in 0..3 {
        let invoice = recipient
            .create_invoice(1_000 * (i + 1), &format!("payment {i}"), 3600)
            .await
            .unwrap();
        provider.pay_invoice(&invoice.bolt11).await.unwrap();
    }

    let payments = provider.list_payments(10).await.unwrap();
    assert_eq!(payments.len(), 3);
}

#[tokio::test]
async fn get_node_pubkey_returns_mock_pubkey() {
    let provider = MockLightningProvider::new();
    let pubkey = provider.get_node_pubkey().await;
    assert!(pubkey.is_some());
    let pk = pubkey.unwrap();
    assert_eq!(pk.len(), 66);
    assert!(pk.starts_with("02"));
}

#[tokio::test]
async fn keysend_and_get_node_pubkey_roundtrip() {
    let sender = MockLightningProvider::new();
    let recipient = MockLightningProvider::new();

    // Get recipient's pubkey (simulates LightningInfo exchange).
    let dest_pubkey = recipient.get_node_pubkey().await.unwrap();

    // Send keysend.
    let details = sender.keysend(&dest_pubkey, 5_000, Some("test keysend")).await.unwrap();
    assert_eq!(details.status, PaymentStatus::Settled);
    assert_eq!(details.amount_msat, 5_000);
    assert!(details.preimage.is_some());

    // Verify preimage → hash relationship.
    let preimage_hex = details.preimage.unwrap();
    let preimage_bytes = hex::decode(&preimage_hex).unwrap();
    let hash_bytes: [u8; 32] = sha2::Sha256::digest(&preimage_bytes).into();
    assert_eq!(hex::encode(hash_bytes), details.payment_hash);
}

