use konsensus_lightning::decrypt_and_load_scb_backup;

#[test]
fn restore_is_locked_before_decryption_or_any_storage_write() {
    let tmp = tempfile::tempdir().unwrap();
    let destination = tmp.path().join("must-not-exist");
    let result = decrypt_and_load_scb_backup(
        b"invalid backup",
        &[0; 32],
        [0; 64],
        &destination,
        "regtest",
        "http://127.0.0.1:1",
    );
    let error = result.err().expect("restore must be locked").to_string();
    assert!(error.contains("disabled"), "{error}");
    assert!(error.contains("revoked commitment"), "{error}");
    assert!(error.contains("move-home"), "{error}");
    assert!(!destination.exists());
}

#[test]
fn restored_force_close_entry_point_has_no_bypass() {
    let tmp = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_entropy_seed_bytes([11; 64]);
    builder.set_storage_dir_path(tmp.path().to_str().unwrap().to_owned());
    let node = builder.build().unwrap();
    let error = konsensus_lightning::force_close_restored_channels(&node).unwrap_err();
    assert!(error.to_string().contains("disabled"));
    assert!(!node.status().is_running);
}
