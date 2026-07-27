use std::fs;

#[test]
fn scb_export_reads_persisted_monitor_store_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fs_store = tmp.path().join("fs_store");
    fs::create_dir_all(fs_store.join("monitors")).expect("mkdir monitors");
    fs::create_dir_all(fs_store.join("monitor_updates").join("chan-1")).expect("mkdir updates");

    fs::write(fs_store.join("monitors").join("chan-1"), b"monitor-state").expect("write monitor");
    fs::write(
        fs_store.join("monitor_updates").join("chan-1").join("1"),
        b"monitor-update",
    )
    .expect("write update");

    let scb_path = tmp.path().join("scb.bin");
    konsensus_lightning::scb_export::write_monitor_store_scb(tmp.path(), &scb_path)
        .expect("export scb");

    let blob = fs::read(&scb_path).expect("read scb");
    assert!(blob.windows("monitor-state".len()).any(|w| w == b"monitor-state"));
    assert!(blob.windows("monitor-update".len()).any(|w| w == b"monitor-update"));
}
