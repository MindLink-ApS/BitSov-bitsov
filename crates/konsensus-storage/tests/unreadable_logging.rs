//! Dedicated process so concurrent tests cannot change tracing callsite interest.
use konsensus_core::{kind::KIND_CHAT, NodeId, PaymentProof, Recipient, UkmEnvelopeBuilder};
use konsensus_storage::{EncryptedStorage, Room, SqliteStorage, Storage};
use std::sync::Arc;

#[tokio::test]
async fn unreadable_logs_only_identifiers_and_fixed_warnings() {
    use std::io::Write;
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Capture(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || capture.clone())
        .finish();
    // This integration test has its own process: one subscriber for all polls.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let store = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    let row = Room::new(
        "SENTINEL-SECRET-CONTENT".into(),
        NodeId::from_bytes([1; 32]),
    );
    store.inner().create_room(&row).await.unwrap();
    let recipient = Recipient::Node(NodeId::from_bytes([2; 32]));
    let message = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        row.created_by,
        recipient,
        b"SENTINEL-MESSAGE-CONTENT".to_vec(),
        PaymentProof::new([1; 32], [2; 32], 10),
    )
    .build();
    store.inner().store_message(&message).await.unwrap();
    for _ in 0..2 {
        let rows = store.list_rooms_with_diagnostics().await.unwrap();
        assert_eq!(rows.unreadable_count, 1);
        assert!(rows.items.is_empty());
        let messages = store
            .get_messages_for_recipient_with_diagnostics(&recipient, 10, None)
            .await
            .unwrap();
        assert_eq!(messages.unreadable_count, 1);
        assert!(messages.items.is_empty());
    }
    let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(logs.contains(&row.id.to_string()));
    assert_eq!(logs.matches("storage_key_mismatch:").count(), 1);
    assert_eq!(logs.matches("at-rest decrypt failed").count(), 4);
    assert!(logs.contains(&message.id.to_string()));
    assert!(!logs.contains("SENTINEL"));
    assert!(!logs.contains(&row.created_by.to_hex()));
    assert!(!logs.contains("hex decode"));
    assert!(!logs.contains(&hex::encode([7; 32])));
}
