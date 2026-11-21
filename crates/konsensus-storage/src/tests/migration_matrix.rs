use super::{EmbeddedMigrations, SqliteStorage};
use crate::StorageError;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::borrow::Cow;
use std::path::Path;

async fn connect(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap()
}

fn prefix(count: usize) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            EmbeddedMigrations::migrations()
                .into_iter()
                .take(count)
                .collect(),
        ),
        ..Migrator::DEFAULT
    }
}

async fn schema(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn ledger(pool: &SqlitePool) -> Vec<(i64, String, bool, Vec<u8>)> {
    sqlx::query_as(
        "SELECT version, description, success, checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn insert_peer(pool: &SqlitePool) {
    sqlx::query("INSERT INTO peers (node_id, display_name, metadata_json) VALUES ('sentinel', 'retained', '{\"value\":7}')")
        .execute(pool)
        .await
        .unwrap();
}

async fn assert_peer(pool: &SqlitePool) {
    let row: (String, String) =
        sqlx::query_as("SELECT display_name, metadata_json FROM peers WHERE node_id = 'sentinel'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(row, ("retained".into(), "{\"value\":7}".into()));
}

#[tokio::test]
async fn every_released_prefix_upgrades_to_the_complete_schema() {
    let dir = tempfile::tempdir().unwrap();
    let fresh_path = dir.path().join("fresh.sqlite");
    let fresh = SqliteStorage::open_with_migrations_dir(fresh_path.to_str().unwrap(), None)
        .await
        .unwrap();
    let expected_schema = schema(fresh.pool()).await;
    let expected_ledger = ledger(fresh.pool()).await;
    let count = EmbeddedMigrations::migrations().len();
    fresh.pool().close().await;

    // Each suffix runs every remaining migration, preserving the reserved gap.
    for applied in 0..=count {
        let path = dir.path().join(format!("prefix-{applied}.sqlite"));
        let pool = connect(&path).await;
        prefix(applied).run(&pool).await.unwrap();
        if applied > 0 {
            insert_peer(&pool).await;
        }
        pool.close().await;

        let upgraded = SqliteStorage::open_with_migrations_dir(path.to_str().unwrap(), None)
            .await
            .unwrap_or_else(|e| panic!("upgrade prefix {applied}: {e}"));
        assert_eq!(
            schema(upgraded.pool()).await,
            expected_schema,
            "prefix {applied}"
        );
        assert_eq!(
            ledger(upgraded.pool()).await,
            expected_ledger,
            "prefix {applied}"
        );
        if applied > 0 {
            assert_peer(upgraded.pool()).await;
        }
        upgraded.pool().close().await;
    }
}

#[tokio::test]
async fn unknown_gap_and_future_versions_are_refused_without_pending_changes() {
    let dir = tempfile::tempdir().unwrap();
    // The unused historical slot and two newer-version boundaries.
    for version in [34_i64, 43, i64::MAX] {
        for applied in [1, EmbeddedMigrations::migrations().len()] {
            let path = dir
                .path()
                .join(format!("unknown-{version}-{applied}.sqlite"));
            let pool = connect(&path).await;
            prefix(applied).run(&pool).await.unwrap();
            insert_peer(&pool).await;
            sqlx::query("INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, 'unrecognized', TRUE, X'00', 0)")
                .bind(version)
                .execute(&pool)
                .await
                .unwrap();
            let before_schema = schema(&pool).await;
            let before_ledger = ledger(&pool).await;
            pool.close().await;

            let err =
                match SqliteStorage::open_with_migrations_dir(path.to_str().unwrap(), None).await {
                    Ok(db) => {
                        db.pool().close().await;
                        panic!("unknown version {version} must refuse startup");
                    }
                    Err(err) => err,
                };
            assert!(
                matches!(err, StorageError::Migration(MigrateError::VersionMissing(v)) if v == version)
            );
            assert!(err.to_string().contains(&version.to_string()));
            let pool = connect(&path).await;
            assert_eq!(schema(&pool).await, before_schema);
            assert_eq!(ledger(&pool).await, before_ledger);
            assert_peer(&pool).await;
            pool.close().await;
        }
    }
}

#[tokio::test]
async fn changed_applied_checksum_is_refused_before_any_pending_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checksum.sqlite");
    let pool = connect(&path).await;
    prefix(1).run(&pool).await.unwrap();
    insert_peer(&pool).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let before_schema = schema(&pool).await;
    let before_ledger = ledger(&pool).await;
    pool.close().await;
    let result = SqliteStorage::open_with_migrations_dir(path.to_str().unwrap(), None).await;
    assert!(matches!(
        result,
        Err(StorageError::Migration(MigrateError::VersionMismatch(1)))
    ));
    let pool = connect(&path).await;
    assert_eq!(schema(&pool).await, before_schema);
    assert_eq!(ledger(&pool).await, before_ledger);
    assert_peer(&pool).await;
    pool.close().await;
}

#[tokio::test]
async fn each_failed_migration_preserves_previous_schema_rows_and_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let source = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"));
    let migrations = EmbeddedMigrations::migrations();
    for (index, migration) in migrations.iter().enumerate() {
        let external = dir.path().join(format!("migrations-{}", migration.version));
        std::fs::create_dir(&external).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file()
                && entry.path().extension().is_some_and(|e| e == "sql")
            {
                let name = entry.file_name();
                let name_str = name.to_str().unwrap();
                let version: i64 = name_str.split('_').next().unwrap().parse().unwrap();
                if version == migration.version {
                    // Fail after real DDL and a data write, never before them.
                    let sql = format!("{}\nCREATE TABLE rollback_probe (id INTEGER);\nUPDATE peers SET display_name = 'changed';\nINSERT INTO absent_failure_target VALUES (1);", migration.sql);
                    std::fs::write(external.join(name), sql).unwrap();
                } else {
                    std::fs::copy(entry.path(), external.join(name)).unwrap();
                }
            }
        }
        let path = dir
            .path()
            .join(format!("failed-{}.sqlite", migration.version));
        let pool = connect(&path).await;
        prefix(index).run(&pool).await.unwrap();
        if index > 0 {
            insert_peer(&pool).await;
        }
        let before_schema = schema(&pool).await;
        let before_ledger = ledger(&pool).await;
        pool.close().await;
        let result =
            SqliteStorage::open_with_migrations_dir(path.to_str().unwrap(), Some(&external)).await;
        assert!(result
            .as_ref()
            .err()
            .unwrap()
            .to_string()
            .contains("absent_failure_target"));
        assert!(
            matches!(result, Err(StorageError::Migration(MigrateError::ExecuteMigration(_, v))) if v == migration.version),
            "migration {} must fail at injected SQL",
            migration.version
        );
        let pool = connect(&path).await;
        assert_eq!(
            schema(&pool).await,
            before_schema,
            "migration {}",
            migration.version
        );
        assert_eq!(
            ledger(&pool).await,
            before_ledger,
            "migration {}",
            migration.version
        );
        if index > 0 {
            assert_peer(&pool).await;
        }
        pool.close().await;
        // A clean retry proves failure neither poisoned nor advanced the schema.
        let retried = SqliteStorage::open_with_migrations_dir(path.to_str().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(ledger(retried.pool()).await.len(), migrations.len());
        retried.pool().close().await;
    }
}
