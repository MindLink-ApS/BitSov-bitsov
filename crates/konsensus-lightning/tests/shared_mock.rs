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
