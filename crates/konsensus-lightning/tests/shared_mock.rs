use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};
use konsensus_lightning::shared_mock::SharedMockProvider;

#[tokio::test]
async fn recipient_settlement_is_shared_bound_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let a = SharedMockProvider::new(&path, "a", 10_000).unwrap();
    let b = SharedMockProvider::new(&path, "b", 0).unwrap();
    let stranger = SharedMockProvider::new(&path, "c", 0).unwrap();
    let invoice = b
        .create_invoice(2_345, "recipient price", 60)
        .await
        .unwrap();
    let parsed: lightning_invoice::Bolt11Invoice = invoice.bolt11.parse().unwrap();
    assert_eq!(parsed.currency(), lightning_invoice::Currency::Regtest);
    assert_eq!(parsed.amount_milli_satoshis(), Some(2_345));
    assert_eq!(
        b.get_payment_status(&invoice.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Pending
    );
    let payment = a.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(payment.direction, PaymentDirection::Outgoing);
    let received = b.get_payment_status(&invoice.payment_hash).await.unwrap();
    assert_eq!(received.direction, PaymentDirection::Incoming);
    assert_eq!(received.status, PaymentStatus::Settled);
    assert_eq!(received.preimage, payment.preimage);
    assert!(stranger
        .get_payment_status(&invoice.payment_hash)
        .await
        .is_err());
    a.pay_invoice(&invoice.bolt11).await.unwrap();
    assert_eq!(a.get_balance_msat().await.unwrap(), 7_655);
    assert_eq!(b.get_balance_msat().await.unwrap(), 2_345);
    assert!(stranger.pay_invoice(&invoice.bolt11).await.is_err());
    let a_restarted = SharedMockProvider::new(&path, "a", 10_000).unwrap();
    assert_eq!(a_restarted.get_balance_msat().await.unwrap(), 7_655);
}

#[tokio::test]
async fn stateless_quote_writes_only_at_settlement_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let a = SharedMockProvider::new(&path, "a", 10_000).unwrap();
    let b = SharedMockProvider::new(&path, "b", 0).unwrap();
    let c = SharedMockProvider::new(&path, "c", 0).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let count = || db.query_row("SELECT COUNT(*) FROM invoices", [], |r| r.get::<_, u64>(0)).unwrap();
    assert_eq!(count(), 0);
    let quote = b.create_stateless_invoice(2345, "bound quote", 60).await.unwrap();
    assert_eq!(count(), 0, "quote persisted before settlement");
    assert!(b.list_payments(10).await.unwrap().is_empty());
    assert!(b.get_payment_status(&quote.payment_hash).await.is_err());
    drop(b);
    let b = SharedMockProvider::new(&path, "b", 0).unwrap();
    // A failed attempt must not materialize the pending quote either.
    assert!(c.pay_invoice(&quote.bolt11).await.is_err());
    assert_eq!(count(), 0);
    let paid = a.pay_invoice(&quote.bolt11).await.unwrap();
    assert_eq!(count(), 1);
    let receipt = b.get_payment_status(&quote.payment_hash).await.unwrap();
    assert_eq!(receipt.status, PaymentStatus::Settled);
    assert_eq!(receipt.direction, PaymentDirection::Incoming);
    assert_eq!(receipt.preimage, paid.preimage);
    assert!(c.get_payment_status(&quote.payment_hash).await.is_err());
    a.pay_invoice(&quote.bolt11).await.unwrap();
    assert_eq!(a.get_balance_msat().await.unwrap(), 7655);
    assert_eq!(b.get_balance_msat().await.unwrap(), 2345);
    assert_eq!(count(), 1);
}
