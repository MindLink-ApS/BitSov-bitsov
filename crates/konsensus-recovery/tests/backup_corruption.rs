#[path = "../../konsensus-lightning/src/scb_export.rs"]
mod scb_export;

use konsensus_recovery::{BackupError, BackupIndex, RecoveryKeys};

#[test]
fn encrypted_export_refuses_every_truncation_and_single_byte_change() {
    let dir = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("ldk_node_data.sqlite")).unwrap();
    conn.execute("CREATE TABLE ldk_node_data (primary_namespace TEXT, secondary_namespace TEXT, key TEXT, value BLOB)", []).unwrap();
    conn.execute(
        "INSERT INTO ldk_node_data VALUES ('', '', 'manager', ?1)",
        [b"opaque manager".as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO ldk_node_data VALUES ('monitor_updates', 'channel', '1', ?1)",
        [b"opaque update".as_slice()],
    )
    .unwrap();
    let path = dir.path().join("export.scb");
    scb_export::write_monitor_store_scb(dir.path(), &path).unwrap();
    let plaintext = std::fs::read(&path).unwrap();
    let encrypted = konsensus_crypto::scb::encrypt_scb(&plaintext, &[7; 32]).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&[0; 32]).unwrap();
    assert!(BackupIndex::decrypt(&encrypted, &[7; 32], &keys)
        .unwrap()
        .channels()
        .is_empty());
    for end in 0..encrypted.len() {
        assert_eq!(
            BackupIndex::decrypt(&encrypted[..end], &[7; 32], &keys),
            Err(BackupError::Decryption),
            "truncated at {end}"
        );
    }
    for offset in 0..encrypted.len() {
        let mut corrupted = encrypted.clone();
        corrupted[offset] ^= 1;
        assert_eq!(
            BackupIndex::decrypt(&corrupted, &[7; 32], &keys),
            Err(BackupError::Decryption),
            "modified at {offset}"
        );
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ldk_node_data", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(std::fs::read(&path).unwrap(), plaintext);
}
