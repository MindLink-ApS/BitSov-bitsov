//! Application-boundary regression: a stale/replayed failure notification is a
//! wake-up hint, never authority to replace a successful persisted receipt.
//! Raw LDK PaymentSent -> PaymentFailed is covered by the vendored lib tests.
use super::*;
use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning::util::persist::KVStoreSync;
use ldk_node::lightning::util::ser::Writeable;
use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settlement_reread_after_late_failure_hint_retains_success_and_proof() {
    use bitcoin::hashes::{sha256, Hash};
    for include_hash in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            ldk_node::io::sqlite_store::SqliteStore::new(dir.path().to_owned(), None, None)
                .unwrap(),
        );
        let preimage = PaymentPreimage([81; 32]);
        let hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
        let id = PaymentId(hash.0);
        let receipt = ldk_node::payment::PaymentDetails {
            id,
            kind: LdkPaymentKind::Bolt11 {
                hash,
                preimage: Some(preimage),
                secret: None,
            },
            amount_msat: Some(10_000),
            fee_paid_msat: Some(42),
            direction: ldk_node::payment::PaymentDirection::Outbound,
            status: LdkPaymentStatus::Succeeded,
            latest_update_timestamp: 1_700_000_000,
        };
        KVStoreSync::write(
            &*store,
            "payments",
            "",
            &hex::encode(id.0),
            receipt.encode(),
        )
        .unwrap();
        // Restore a stale application notification through the real persistent
        // queue, then run the production drainer and broadcast consumer.
        let event = ldk_node::Event::PaymentFailed {
            payment_id: Some(id),
            payment_hash: include_hash.then_some(hash),
            reason: None,
        };
        let mut queued = Vec::new();
        1u16.write(&mut queued).unwrap();
        event.write(&mut queued).unwrap();
        KVStoreSync::write(&*store, "", "", "events", queued).unwrap();
        let mut builder = ldk_node::Builder::new();
        builder.set_network(bitcoin::Network::Regtest);
        builder.set_entropy_seed_bytes([82; 64]);
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        let node = Arc::new(builder.build_with_store(store).unwrap());
        let provider = LdkProvider::from_node(node.clone());
        let polled_hash = hex::encode(hash.0);
        assert_eq!(
            provider
                .get_payment_status(&polled_hash)
                .await
                .unwrap()
                .status,
            PaymentStatus::Settled
        );
        let mut updates = provider.outgoing_payment_updates().unwrap();
        provider.drainer_shutdown.store(false, Ordering::Relaxed);
        LdkProvider::spawn_event_drainer(
            node.clone(),
            provider.drainer_shutdown.clone(),
            Arc::new(ScbProducer::new(dir.path().to_owned(), None, 2, &[82; 64])),
            provider.inbound_tx.clone(),
            provider.outgoing_tx.clone(),
            Default::default(),
        );
        let hint = tokio::time::timeout(Duration::from_secs(5), updates.next())
            .await
            .expect("late failure did not wake settlement poll")
            .unwrap();
        assert_eq!(hint, polled_hash);
        let settled = provider.get_payment_status(&hint).await.unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(settled.preimage, Some(hex::encode(preimage.0)));
        assert_eq!(settled.amount_msat, 10_000);
        assert_eq!(settled.fee_msat, Some(42));
        assert_eq!(node.payment(&id).unwrap(), receipt);
        // Drop stops the drainer even if an assertion above panics.
        drop(provider);
    }
}
