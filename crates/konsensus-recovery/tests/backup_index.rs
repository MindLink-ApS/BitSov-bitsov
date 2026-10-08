//! End-to-end format contract with the actual pinned LDK writer, exporter and rotation.
#[path = "../../konsensus-lightning/src/scb_export.rs"]
mod scb_export;
#[path = "../../konsensus-lightning/src/scb_rotate.rs"]
mod scb_rotate;

use konsensus_recovery::{BackupError, BackupIndex, RecoveryKeys, MAX_BACKUP_BYTES};
use lightning::ln::functional_test_utils::*;
use lightning::ln::msgs::BaseMessageHandler;
use lightning::util::ser::Writeable;
use proptest::prelude::*;

#[test]
fn exported_stale_backups_keep_funding_and_verified_scripts() {
    for anchors in [false, true] {
        let mon_cfg = create_chanmon_cfgs(2);
        let cfg = create_node_cfgs(2, &mon_cfg);
        let user = if anchors {
            test_default_anchors_channel_config()
        } else {
            test_default_channel_config()
        };
        let managers = create_node_chanmgrs(2, &cfg, &[Some(user.clone()), Some(user)]);
        let nodes = create_network(2, &cfg, &managers);
        let (_, _, channel_id, funding) = create_announced_chan_between_nodes(&nodes, 0, 1);
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("fs_store/monitors");
        std::fs::create_dir_all(&store).unwrap();
        let monitor_bytes = || {
            nodes[0]
                .chain_monitor
                .chain_monitor
                .get_monitor(channel_id)
                .unwrap()
                .encode()
        };
        std::fs::write(store.join("channel"), monitor_bytes()).unwrap();
        // Manager and updates remain opaque, even if their contents are not LDK objects.
        std::fs::write(dir.path().join("fs_store/manager"), b"never load this").unwrap();
        let scb = dir.path().join("scb.bin");
        scb_export::write_monitor_store_scb(dir.path(), &scb).unwrap();
        let rotated = scb_rotate::rotate_scb_backup(
            &scb_rotate::ScbRotationConfig {
                scb_path: scb,
                backup_dir: dir.path().join("backups"),
                rotation_count: 1,
            },
            &[7; 32],
        )
        .unwrap();
        let encrypted = std::fs::read(rotated.latest_path).unwrap();
        let keys = RecoveryKeys::from_ldk_seed(&[0; 32]).unwrap();
        let store_before = monitor_bytes();
        let stale = BackupIndex::decrypt(&encrypted, &[7; 32], &keys).unwrap();
        assert_eq!(stale.channels().len(), 1);
        assert_eq!(std::fs::read(store.join("channel")).unwrap(), store_before);
        let channel = &stale.channels()[0];
        assert_eq!(channel.funding_outpoint.txid, funding.compute_txid());
        assert_eq!(
            channel.counterparty_node_id,
            nodes[1].node.get_our_node_id()
        );
        assert_eq!(channel.funding_outpoint.vout, 0);
        assert_eq!(channel.channel_value_satoshis, 100_000);
        assert_eq!(channel.best_block_height, nodes[0].best_block_info().1);
        assert!(keys.scripts().contains(&channel.to_remote));
        assert_eq!(
            channel.to_remote.kind,
            if anchors {
                konsensus_recovery::OutputKind::AnchorToRemote
            } else {
                konsensus_recovery::OutputKind::StaticRemoteKey
            }
        );
        send_payment(&nodes[0], &[&nodes[1]], 1000);
        std::fs::write(store.join("channel"), monitor_bytes()).unwrap();
        scb_export::write_monitor_store_scb(dir.path(), &dir.path().join("new.bin")).unwrap();
        let fresh =
            BackupIndex::from_plaintext(&std::fs::read(dir.path().join("new.bin")).unwrap(), &keys)
                .unwrap();
        assert_eq!(
            channel.funding_outpoint,
            fresh.channels()[0].funding_outpoint
        );
        assert_eq!(channel.to_remote, fresh.channels()[0].to_remote);
        assert_ne!(
            channel.holder_commitment_number,
            fresh.channels()[0].holder_commitment_number
        );
        assert!(BackupIndex::decrypt(&encrypted, &[8; 32], &keys).is_err());
        assert!(BackupIndex::decrypt(
            &encrypted,
            &[7; 32],
            &RecoveryKeys::from_ldk_seed(&[1; 32]).unwrap()
        )
        .is_err());
        let plaintext = scb_rotate::decrypt_scb_backup(&encrypted, &[7; 32]).unwrap();
        for end in 0..encrypted.len() {
            assert!(BackupIndex::decrypt(&encrypted[..end], &[7; 32], &keys).is_err());
        }
        for end in 0..plaintext.len() {
            assert!(
                BackupIndex::from_plaintext(&plaintext[..end], &keys).is_err(),
                "truncated at {end}"
            );
        }
        // Mutate every byte in the authenticated plaintext, including deep
        // count/length fields. A valid metadata-only mutation may be accepted;
        // it must still yield a bounded index of seed-verified scripts.
        for offset in 0..plaintext.len() {
            let mut mutated = plaintext.clone();
            mutated[offset] ^= 0xff;
            if let Ok(index) = BackupIndex::from_plaintext(&mutated, &keys) {
                assert!(index.channels().len() <= 1);
                assert!(index
                    .channels()
                    .iter()
                    .all(|c| keys.scripts().contains(&c.to_remote)));
            }
        }
        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            BackupIndex::decrypt(&tampered, &[7; 32], &keys),
            Err(BackupError::Decryption)
        );

        // Actual ldk-node MonitorUpdatingPersister adds a two-byte sentinel.
        let original = monitor_bytes();
        let mut persisted = vec![0xff, 0xff];
        persisted.extend_from_slice(&original);
        std::fs::write(store.join("channel"), persisted).unwrap();
        let envelope = dir.path().join("sentinel.scb");
        scb_export::write_monitor_store_scb(dir.path(), &envelope).unwrap();
        assert!(BackupIndex::from_plaintext(&std::fs::read(envelope).unwrap(), &keys).is_ok());

        // Primary production store backend, using the real exporter.
        let sql_dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(sql_dir.path().join("ldk_node_data.sqlite")).unwrap();
        conn.execute("CREATE TABLE ldk_node_data (primary_namespace TEXT, secondary_namespace TEXT, key TEXT, value BLOB)", []).unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES ('monitors', '', 'channel', ?1)",
            [monitor_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES ('monitor_updates', 'channel', '999', ?1)",
            [b"opaque update".as_slice()],
        )
        .unwrap();
        let sql_scb = sql_dir.path().join("scb.bin");
        scb_export::write_monitor_store_scb(sql_dir.path(), &sql_scb).unwrap();
        assert_eq!(
            BackupIndex::from_plaintext(&std::fs::read(&sql_scb).unwrap(), &keys).unwrap(),
            fresh
        );
        conn.execute("UPDATE ldk_node_data SET primary_namespace = 'archived_monitors' WHERE primary_namespace = 'monitors'", []).unwrap();
        scb_export::write_monitor_store_scb(sql_dir.path(), &sql_scb).unwrap();
        assert!(
            BackupIndex::from_plaintext(&std::fs::read(&sql_scb).unwrap(), &keys)
                .unwrap()
                .channels()[0]
                .archived
        );
        conn.execute(
            "INSERT INTO ldk_node_data VALUES ('monitors', '', 'duplicate', ?1)",
            [monitor_bytes()],
        )
        .unwrap();
        scb_export::write_monitor_store_scb(sql_dir.path(), &sql_scb).unwrap();
        assert_eq!(
            BackupIndex::from_plaintext(&std::fs::read(&sql_scb).unwrap(), &keys),
            Err(BackupError::DuplicateChannel)
        );

        // Exercise HTLC-bearing snapshots too, without ever applying an update
        // in the recovery parser.
        let payment = route_payment(&nodes[0], &[&nodes[1]], 5_000_000);
        std::fs::write(store.join("channel"), monitor_bytes()).unwrap();
        scb_export::write_monitor_store_scb(dir.path(), &dir.path().join("inflight.bin")).unwrap();
        let inflight = BackupIndex::from_plaintext(
            &std::fs::read(dir.path().join("inflight.bin")).unwrap(),
            &keys,
        )
        .unwrap();
        assert_eq!(channel.to_remote, inflight.channels()[0].to_remote);
        claim_payment(&nodes[0], &[&nodes[1]], payment.0);

        // A peer commitment with an unresolved HTLC populates locktimed claim
        // packages, then pending claims as the timeout matures. Neither the
        // operational state nor its signed transactions may escape the index.
        route_payment(&nodes[0], &[&nodes[1]], 5_000_000);
        nodes[1]
            .node
            .force_close_broadcasting_latest_txn(
                &channel_id,
                &nodes[0].node.get_our_node_id(),
                "fixture close".into(),
            )
            .unwrap();
        // Test-only access to the live peer's current commitment also works
        // for anchor closes, whose actual broadcast goes through fee bumping.
        let close = lightning::get_local_commitment_txn!(nodes[1], channel_id)[0].clone();
        mine_transaction(&nodes[0], &close);
        for depth in [0, 200] {
            if depth != 0 {
                connect_blocks(&nodes[0], depth);
            }
            std::fs::write(store.join("channel"), monitor_bytes()).unwrap();
            let closed_scb = dir.path().join("closed.bin");
            scb_export::write_monitor_store_scb(dir.path(), &closed_scb).unwrap();
            let closed =
                BackupIndex::from_plaintext(&std::fs::read(closed_scb).unwrap(), &keys).unwrap();
            assert_eq!(
                closed.channels()[0].funding_outpoint,
                channel.funding_outpoint
            );
            assert_eq!(closed.channels()[0].to_remote, channel.to_remote);
            assert_eq!(
                closed.channels()[0].best_block_height,
                nodes[0].best_block_info().1
            );
        }
        assert!(!nodes[0]
            .tx_broadcaster
            .txn_broadcasted
            .lock()
            .unwrap()
            .is_empty());
        for node in &nodes {
            node.node.get_and_clear_pending_events();
            node.node.get_and_clear_pending_msg_events();
            node.chain_monitor.added_monitors.lock().unwrap().clear();
        }
    }
}

fn keys() -> &'static RecoveryKeys {
    static KEYS: std::sync::OnceLock<RecoveryKeys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| RecoveryKeys::from_ldk_seed(&[0; 32]).unwrap())
}

#[test]
fn rejects_oversize_and_unbounded_counts_before_allocation() {
    let oversized = vec![0; MAX_BACKUP_BYTES + 1];
    assert_eq!(
        BackupIndex::decrypt(&oversized, &[0; 32], keys()),
        Err(BackupError::LimitExceeded)
    );
    assert_eq!(
        BackupIndex::from_plaintext(&oversized, keys()),
        Err(BackupError::LimitExceeded)
    );
    let mut blob = b"BSCBKV01".to_vec();
    blob.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        BackupIndex::from_plaintext(&blob, keys()),
        Err(BackupError::LimitExceeded)
    );
    blob[8..].copy_from_slice(&0u32.to_be_bytes());
    assert!(BackupIndex::from_plaintext(&blob, keys())
        .unwrap()
        .channels()
        .is_empty());
    blob.push(1);
    assert_eq!(
        BackupIndex::from_plaintext(&blob, keys()),
        Err(BackupError::InvalidFormat)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_decoder_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = BackupIndex::decrypt(&bytes, &[0; 32], keys());
        let _ = BackupIndex::from_plaintext(&bytes, keys());
        // Bypass the outer magic gate to exercise framing and monitor parsing.
        let mut blob = b"BSCBKV01".to_vec();
        blob.extend_from_slice(&1u32.to_be_bytes());
        for field in [b"monitors".as_slice(), b"", b"channel"] {
            blob.extend_from_slice(&(field.len() as u16).to_be_bytes());
            blob.extend_from_slice(field);
        }
        blob.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(&bytes);
        let _ = BackupIndex::from_plaintext(&blob, keys());
        let encrypted = konsensus_crypto::scb::encrypt_scb(&blob, &[0; 32]).unwrap();
        let _ = BackupIndex::decrypt(&encrypted, &[0; 32], keys());
    }
}
