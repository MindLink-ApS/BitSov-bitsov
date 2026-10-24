//! Fresh SQLite migrator catalog, round-trips, and upgrade from the previous version.

use std::path::Path;

use konsensus_core::NodeId;

use crate::calendar::{CalendarEventRecord, RsvpRecord};
use crate::contacts::{ContactRepo, ContactRow, SqliteContactRepo};
use crate::encrypted::EncryptedStorage;
use crate::fiat_snapshots::FiatRateSnapshot;
use crate::recovery::{RecoveryScheme, RecoveryStore, SqliteRecoveryStore};
use crate::schema_catalog::{self, ParityCatalog};
use crate::traits::Storage;
use crate::SqliteStorage;

fn sample_event(id: &str, title: &str) -> CalendarEventRecord {
    CalendarEventRecord {
        id: id.to_string(),
        message_id: None,
        organizer: "aa".repeat(32),
        title: title.to_string(),
        description: Some("agenda".into()),
        start_ms: 1_700_000_000_000,
        end_ms: 1_700_000_360_000,
        tz: "UTC".into(),
        location: Some("signet".into()),
        attendees_json: "[]".into(),
        recurrence_json: None,
        color: None,
        created_at: String::new(),
        parent_id: None,
    }
}

fn sample_snapshot(rate: f64) -> FiatRateSnapshot {
    FiatRateSnapshot {
        date: "2026-04-21".into(),
        currency: "USD".into(),
        rate,
        source: "MempoolSpace".into(),
        created_at: String::new(),
    }
}

async fn fresh_sqlite() -> SqliteStorage {
    SqliteStorage::in_memory()
        .await
        .expect("migrate empty sqlite")
}

#[tokio::test]
async fn fresh_sqlite_catalog_matches_postgres_shape() {
    let db = fresh_sqlite().await;
    let catalog: ParityCatalog = schema_catalog::load_sqlite(db.pool()).await;
    schema_catalog::assert_parity(&catalog);
}

#[tokio::test]
async fn main_032_sqlite_plus_033_matches_fresh_install() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/main_032/sqlite.sql"))
        .execute(&pool)
        .await
        .expect("apply frozen main migrations through 032");
    sqlx::raw_sql(include_str!(
        "../../migrations/033_calendar_and_schema_parity.sql"
    ))
        .execute(&pool)
        .await
        .expect("upgrade main with only migration 033");
    let upgraded = schema_catalog::load_sqlite(&pool).await;
    schema_catalog::assert_parity(&upgraded);
    let fresh = fresh_sqlite().await;
    assert_eq!(upgraded, schema_catalog::load_sqlite(fresh.pool()).await);
}

#[tokio::test]
async fn fresh_sqlite_fiat_and_calendar_round_trip_without_hand_built_tables() {
    let db = fresh_sqlite().await;

    db.store_fiat_rate_snapshot(&sample_snapshot(65_000.5))
        .await
        .expect("store fiat");
    db.store_fiat_rate_snapshot(&sample_snapshot(66_000.0))
        .await
        .expect("upsert fiat");
    let snaps = db
        .list_fiat_rate_snapshots("2026-04-01", "2026-04-30")
        .await
        .expect("list fiat");
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].rate, 66_000.0);
    assert_eq!(snaps[0].source, "MempoolSpace");
    assert!(!snaps[0].created_at.is_empty());

    let event = sample_event("event-1", "signet standup");
    db.store_calendar_event(&event).await.expect("store event");
    let stored = db
        .get_calendar_event("event-1")
        .await
        .expect("get event")
        .expect("event row");
    assert_eq!(stored.title, "signet standup");
    assert_eq!(stored.start_ms, event.start_ms);
    assert_eq!(stored.end_ms, event.end_ms);
    assert_eq!(stored.tz, "UTC");
    assert!(!stored.created_at.is_empty());

    let mut updated = event.clone();
    updated.title = "signet standup moved".into();
    updated.created_at.clear();
    db.store_calendar_event(&updated)
        .await
        .expect("upsert event");
    let again = db.get_calendar_event("event-1").await.unwrap().unwrap();
    assert_eq!(again.title, "signet standup moved");
    assert_eq!(again.created_at, stored.created_at);

    let rsvp = RsvpRecord {
        id: "rsvp-1".into(),
        event_id: "event-1".into(),
        responder: "bb".repeat(32),
        response: "accepted".into(),
        comment: Some("ok".into()),
        created_at: String::new(),
    };
    db.store_rsvp(&rsvp).await.expect("store rsvp");
    let mut changed = rsvp.clone();
    changed.id = "rsvp-2".into();
    changed.response = "declined".into();
    db.store_rsvp(&changed).await.expect("upsert rsvp");
    let responses: Vec<String> = sqlx::query_scalar(
        "SELECT response FROM calendar_rsvps WHERE event_id = 'event-1' ORDER BY response",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(responses, vec!["declined".to_string()]);
}

#[tokio::test]
async fn encrypted_wrapper_forwards_fiat_and_leaves_calendar_plaintext() {
    let sqlite = fresh_sqlite().await;
    let pool = sqlite.pool().clone();
    let enc = EncryptedStorage::new(sqlite, &[9u8; 32]);

    enc.store_fiat_rate_snapshot(&sample_snapshot(42.5))
        .await
        .expect("encrypted store forwards fiat");
    let listed = enc
        .list_fiat_rate_snapshots("2026-01-01", "2026-12-31")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].rate, 42.5);
    let raw_rate: f64 =
        sqlx::query_scalar("SELECT rate FROM fiat_rate_snapshots WHERE currency = 'USD'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(raw_rate, 42.5);

    let event = sample_event("event-plain", "plaintext title");
    enc.store_calendar_event(&event).await.unwrap();
    let raw_title: String =
        sqlx::query_scalar("SELECT title FROM calendar_events WHERE id = 'event-plain'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(raw_title, "plaintext title");
}

fn copy_migrations_through(dest: &Path, max_version: i64) {
    let src = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"));
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap();
        let version: i64 = name
            .split_once('_')
            .unwrap()
            .0
            .parse()
            .unwrap_or_else(|_| panic!("migration name {name}"));
        if version <= max_version {
            std::fs::copy(&path, dest.join(name)).unwrap();
        }
    }
}

#[tokio::test]
async fn previous_sqlite_version_upgrades_without_data_loss() {
    let dir = tempfile::tempdir().unwrap();
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    copy_migrations_through(&migrations, 32);
    let db_path = dir.path().join("prev.sqlite");

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(applied, 32);

    let peer = NodeId::from_bytes([9u8; 32]);
    sqlx::query("INSERT INTO peers (node_id, metadata_json) VALUES (?1, '{}')")
        .bind(peer.to_hex())
        .execute(&pool)
        .await
        .unwrap();

    let invite_id = [0x11u8; 16];
    let invitee = [0x22u8; 32];
    let nonce = [0x33u8; 16];
    sqlx::query(
        "INSERT INTO invites_issued (
            id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr,
            max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at
         ) VALUES (?1, ?2, 1700000000, 50000, '127.0.0.1:9735', 5, 1700000100, ?3, 'pending', 1700000000)",
    )
    .bind(invite_id.as_slice())
    .bind(invitee.as_slice())
    .bind(nonce.as_slice())
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE onboarding_state
         SET current_step = 'funding',
             tier = 'full',
             funding_address = 'bcrt1qexample',
             funding_amount_sats_required = 4294967295,
             funding_amount_sats_received = 4294967295,
             last_poll_at = 1700000123,
             funding_evidence = 'wallet_balance_observed'
         WHERE id = 1",
    )
    .execute(&pool)
    .await
    .unwrap();

    let contacts = SqliteContactRepo::new(pool.clone());
    let contact = ContactRow {
        node_id: "cc".repeat(32),
        local_alias: Some("carol".into()),
        claimed_name: None,
        profile_json: "{}".into(),
        avatar_blake3: None,
        verified_identities_json: "[]".into(),
        muted: false,
        blocked: true,
        tags_json: "[]".into(),
        notes: Some("keep".into()),
        created_at: "2026-01-01T00:00:00.000Z".into(),
        updated_at: "2026-01-02T00:00:00.000Z".into(),
    };
    assert!(contacts.upsert_contact(&contact).await.unwrap());

    sqlx::query(
        "INSERT INTO fiat_rate_snapshots (date, currency, rate, source)
         VALUES ('2026-04-20', 'EUR', 60000.0, 'prior')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let recovery = SqliteRecoveryStore::new(pool.clone());
    let scheme = RecoveryScheme {
        id: "scheme-1".into(),
        scheme_type: "shamir_bip39".into(),
        threshold: 2,
        total_shares: 3,
        metadata_json: "{}".into(),
        created_at: "2026-01-01T00:00:00.000Z".into(),
        updated_at: "2026-01-01T00:00:00.000Z".into(),
    };
    assert!(recovery.upsert_recovery_scheme(&scheme).await.unwrap());

    // Hand-built calendar tables, the shape fixtures used before migration 33.
    sqlx::query(
        "CREATE TABLE calendar_events (
            id TEXT PRIMARY KEY,
            message_id TEXT,
            organizer TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            start_ms BIGINT,
            end_ms BIGINT,
            tz TEXT,
            location TEXT,
            attendees_json TEXT,
            recurrence_json TEXT,
            color TEXT,
            created_at TEXT NOT NULL DEFAULT '',
            parent_id TEXT
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO calendar_events (
            id, organizer, title, start_ms, end_ms, tz, attendees_json, created_at
         ) VALUES ('hand-event', 'org', 'kept title', 10, 20, 'UTC', '[]', '2026-01-01T00:00:00Z')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE calendar_rsvps (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            responder TEXT NOT NULL,
            response TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL DEFAULT ''
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO calendar_rsvps (id, event_id, responder, response, created_at)
         VALUES ('hand-rsvp', 'hand-event', 'resp', 'accepted', '2026-01-01T00:00:00Z')",
    )
    .execute(&pool)
    .await
    .unwrap();

    pool.close().await;

    let db = SqliteStorage::open(db_path.to_str().unwrap())
        .await
        .expect("upgrade to current schema");
    let applied: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(applied, 33);

    let loaded_peer = db.get_peer(&peer).await.unwrap().expect("peer survived");
    assert_eq!(loaded_peer.node_id, peer);

    let invites = db.list_invites_issued().await.unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].nonce, nonce);
    assert_eq!(invites[0].state.to_string(), "pending");
    assert_eq!(invites[0].addr, "127.0.0.1:9735");

    let state = db.get_onboarding_state().await.unwrap().unwrap();
    assert_eq!(state.current_step, "funding");
    assert_eq!(state.funding_amount_sats_received, u32::MAX);
    assert_eq!(state.funding_amount_sats_required, Some(u32::MAX));
    assert_eq!(
        state.funding_evidence.as_deref(),
        Some("wallet_balance_observed")
    );
    let confirmations: i64 =
        sqlx::query_scalar("SELECT confirmations FROM onboarding_state WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(confirmations, 0);
    let legacy_txid: Option<String> =
        sqlx::query_scalar("SELECT funding_txid FROM onboarding_state WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(legacy_txid.is_none());

    let kept = SqliteContactRepo::new(db.pool().clone())
        .get_contact(&contact.node_id)
        .await
        .unwrap()
        .unwrap();
    assert!(kept.blocked);
    assert_eq!(kept.notes.as_deref(), Some("keep"));

    let kept_scheme = SqliteRecoveryStore::new(db.pool().clone())
        .get_recovery_scheme("scheme-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept_scheme.threshold, 2);
    assert_eq!(kept_scheme.total_shares, 3);

    let prior = db
        .list_fiat_rate_snapshots("2026-04-20", "2026-04-20")
        .await
        .unwrap();
    assert_eq!(prior.len(), 1);
    assert_eq!(prior[0].rate, 60_000.0);
    assert_eq!(prior[0].source, "prior");

    let hand = db.get_calendar_event("hand-event").await.unwrap().unwrap();
    assert_eq!(hand.title, "kept title");
    assert_eq!(hand.start_ms, 10);

    let duplicate = sqlx::query(
        "INSERT INTO invites_issued (
            id, invitee_pubkey, expiry_unix, addr, nonce, state, created_at
         ) VALUES (?1, ?2, 1700000001, '', ?3, 'pending', 1700000001)",
    )
    .bind([0x44u8; 16].as_slice())
    .bind(invitee.as_slice())
    .bind(nonce.as_slice())
    .execute(db.pool())
    .await;
    assert!(
        duplicate.is_err(),
        "nonce uniqueness must survive the upgrade"
    );

    db.store_rsvp(&RsvpRecord {
        id: "hand-rsvp-2".into(),
        event_id: "hand-event".into(),
        responder: "resp".into(),
        response: "tentative".into(),
        comment: None,
        created_at: String::new(),
    })
    .await
    .unwrap();
    let rsvp_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM calendar_rsvps WHERE event_id = 'hand-event'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(rsvp_count, 1);
    let response: String =
        sqlx::query_scalar("SELECT response FROM calendar_rsvps WHERE event_id = 'hand-event'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(response, "tentative");
}

#[tokio::test]
async fn sqlite_upgrade_rolls_back_when_an_onboarding_column_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    copy_migrations_through(&migrations, 32);
    let db_path = dir.path().join("partial.sqlite");

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE onboarding_state ADD COLUMN funding_amount_sats INTEGER")
        .execute(&pool)
        .await
        .unwrap();
    let peer = NodeId::from_bytes([4u8; 32]);
    sqlx::query("INSERT INTO peers (node_id, metadata_json) VALUES (?1, '{}')")
        .bind(peer.to_hex())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let opened = SqliteStorage::open(db_path.to_str().unwrap()).await;
    assert!(opened.is_err(), "duplicate column must fail the upgrade");

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&db_path))
        .await
        .unwrap();
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 32);
    let calendar: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'calendar_events'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(calendar, 0, "version 33 must roll back calendar creation");
    let confirmations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('onboarding_state') WHERE name = 'confirmations'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(confirmations, 0);
    let peer_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM peers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(peer_count, 1);
}

#[test]
fn schema_parity_migration_stays_in_a_transaction() {
    let sql = include_str!("../../migrations/033_calendar_and_schema_parity.sql");
    assert!(
        !sql.starts_with("-- no-transaction"),
        "version 33 must roll back as a unit"
    );
}
