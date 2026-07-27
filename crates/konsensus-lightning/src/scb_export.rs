//! Export authoritative LDK recovery persistence bytes into a single SCB blob.
//!
//! `LdkProvider::new` currently uses `ldk-node` 0.7's default
//! `Builder::build()` path, which persists its KV store in SQLite:
//! `<storage_dir>/ldk_node_data.sqlite`, table `ldk_node_data`.
//!
//! The exporter reads the channel-manager row plus monitor namespaces from that
//! store directly. A filesystem-store fallback is kept for future migrations,
//! but SQLite is the primary live-mesh path.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

const SCB_BLOB_MAGIC: &[u8; 8] = b"BSCBKV01";
const SQLITE_DB_FILE: &str = "ldk_node_data.sqlite";
const FS_STORE_DIR: &str = "fs_store";
const MONITOR_NAMESPACES: [&str; 3] = ["monitors", "monitor_updates", "archived_monitors"];
const CHANNEL_MANAGER_PRIMARY_NAMESPACE: &str = "";
const CHANNEL_MANAGER_SECONDARY_NAMESPACE: &str = "";
const CHANNEL_MANAGER_KEY: &str = "manager";

#[derive(Debug, thiserror::Error)]
pub enum ScbExportError {
    #[error("SCB export I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("SCB export SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("SCB export field too long (> u16): {0}")]
    FieldTooLong(String),
    #[error("SCB export file too large (> u32): {0}")]
    FileTooLarge(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MonitorEntry {
    primary_namespace: String,
    secondary_namespace: String,
    key: String,
    value: Vec<u8>,
}

pub fn write_monitor_store_scb(
    storage_dir: &Path,
    scb_path: &Path,
) -> Result<usize, ScbExportError> {
    let blob = export_monitor_store_blob(storage_dir)?;
    write_private_atomic(scb_path, &blob)?;
    Ok(blob.len())
}

fn export_monitor_store_blob(storage_dir: &Path) -> Result<Vec<u8>, ScbExportError> {
    let mut entries = if storage_dir.join(SQLITE_DB_FILE).exists() {
        export_sqlite_monitor_entries(storage_dir)?
    } else {
        export_fs_monitor_entries(storage_dir)?
    };
    entries.sort_by(|a, b| {
        (&a.primary_namespace, &a.secondary_namespace, &a.key).cmp(&(
            &b.primary_namespace,
            &b.secondary_namespace,
            &b.key,
        ))
    });

    let mut out = Vec::new();
    out.extend_from_slice(SCB_BLOB_MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    for entry in entries {
        write_field(&mut out, &entry.primary_namespace)?;
        write_field(&mut out, &entry.secondary_namespace)?;
        write_field(&mut out, &entry.key)?;
        let data_len: u32 = entry
            .value
            .len()
            .try_into()
            .map_err(|_| ScbExportError::FileTooLarge(entry.key.clone()))?;
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(&entry.value);
    }

    Ok(out)
}

fn export_sqlite_monitor_entries(storage_dir: &Path) -> Result<Vec<MonitorEntry>, ScbExportError> {
    let db = storage_dir.join(SQLITE_DB_FILE);
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "query_only", true)?;

    let mut stmt = conn.prepare(
        "SELECT primary_namespace, secondary_namespace, key, value \
         FROM ldk_node_data \
         WHERE primary_namespace IN ('monitors', 'monitor_updates', 'archived_monitors') \
            OR (primary_namespace = '' AND secondary_namespace = '' AND key = 'manager')",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(MonitorEntry {
            primary_namespace: row.get(0)?,
            secondary_namespace: row.get(1)?,
            key: row.get(2)?,
            value: row.get(3)?,
        })
    })?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

fn export_fs_monitor_entries(storage_dir: &Path) -> Result<Vec<MonitorEntry>, ScbExportError> {
    let fs_store = storage_dir.join(FS_STORE_DIR);
    let mut entries = Vec::new();

    for namespace in MONITOR_NAMESPACES {
        let dir = fs_store.join(namespace);
        if !dir.exists() {
            continue;
        }
        gather_fs_entries(namespace, &dir, &dir, &mut entries)?;
    }

    let manager_path = fs_store.join(CHANNEL_MANAGER_KEY);
    if manager_path.exists() {
        entries.push(MonitorEntry {
            primary_namespace: CHANNEL_MANAGER_PRIMARY_NAMESPACE.to_string(),
            secondary_namespace: CHANNEL_MANAGER_SECONDARY_NAMESPACE.to_string(),
            key: CHANNEL_MANAGER_KEY.to_string(),
            value: fs::read(manager_path)?,
        });
    }

    Ok(entries)
}

fn gather_fs_entries(
    namespace: &str,
    namespace_root: &Path,
    dir: &Path,
    out: &mut Vec<MonitorEntry>,
) -> Result<(), io::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            gather_fs_entries(namespace, namespace_root, &path, out)?;
        } else if ty.is_file() {
            let rel = path.strip_prefix(namespace_root).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "file outside namespace")
            })?;
            let rel = rel.to_string_lossy().replace('\\', "/");
            let (secondary_namespace, key) = split_fs_key(namespace, &rel);
            out.push(MonitorEntry {
                primary_namespace: namespace.to_string(),
                secondary_namespace,
                key,
                value: fs::read(path)?,
            });
        }
    }
    Ok(())
}

fn split_fs_key(namespace: &str, rel: &str) -> (String, String) {
    if namespace == "monitor_updates" {
        if let Some((secondary, key)) = rel.rsplit_once('/') {
            return (secondary.to_string(), key.to_string());
        }
    }
    (String::new(), rel.to_string())
}

fn write_field(out: &mut Vec<u8>, field: &str) -> Result<(), ScbExportError> {
    let bytes = field.as_bytes();
    let len: u16 = bytes
        .len()
        .try_into()
        .map_err(|_| ScbExportError::FieldTooLong(field.to_string()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), ScbExportError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", rand::random::<u64>()));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
    }

    fs::rename(&tmp_path, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn scb_producer_reads_live_sqlite_monitor_store_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join(SQLITE_DB_FILE);
        let conn = Connection::open(db).unwrap();
        conn.execute(
            "CREATE TABLE ldk_node_data (
                primary_namespace TEXT NOT NULL,
                secondary_namespace TEXT DEFAULT '' NOT NULL,
                key TEXT NOT NULL CHECK (key <> ''),
                value BLOB,
                PRIMARY KEY (primary_namespace, secondary_namespace, key)
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES (?1, ?2, ?3, ?4)",
            params!["monitors", "", "chan-a", b"monitor-bytes"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES (?1, ?2, ?3, ?4)",
            params!["monitor_updates", "chan-a", "1", b"update-1"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES (?1, ?2, ?3, ?4)",
            params!["", "", "manager", b"manager-bytes"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ldk_node_data VALUES (?1, ?2, ?3, ?4)",
            params!["", "", "network_graph", b"not-a-monitor"],
        )
        .unwrap();
        drop(conn);

        let scb_path = tmp.path().join("scb.bin");
        write_monitor_store_scb(tmp.path(), &scb_path).unwrap();
        let blob = fs::read(scb_path).unwrap();

        assert!(blob.starts_with(SCB_BLOB_MAGIC));
        assert!(contains(&blob, b"monitors"));
        assert!(contains(&blob, b"monitor_updates"));
        assert!(contains(&blob, b"manager"));
        assert!(contains(&blob, b"monitor-bytes"));
        assert!(contains(&blob, b"update-1"));
        assert!(contains(&blob, b"manager-bytes"));
        assert!(!contains(&blob, b"network_graph"));
    }

    #[test]
    #[cfg(unix)]
    fn scb_producer_writes_private_plaintext_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let fs_store = tmp.path().join("fs_store");
        fs::create_dir_all(fs_store.join("monitors")).unwrap();
        fs::write(fs_store.join("monitors").join("chan-a"), b"monitor-bytes").unwrap();

        let scb_path = tmp.path().join("scb.bin");
        write_monitor_store_scb(tmp.path(), &scb_path).unwrap();

        let mode = fs::metadata(scb_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn scb_producer_falls_back_to_fs_store_monitor_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let fs_store = tmp.path().join("fs_store");
        fs::create_dir_all(fs_store.join("monitors")).unwrap();
        fs::create_dir_all(fs_store.join("monitor_updates").join("chan-a")).unwrap();
        fs::write(fs_store.join("monitors").join("chan-a"), b"monitor-bytes").unwrap();
        fs::write(fs_store.join("manager"), b"manager-bytes").unwrap();
        fs::write(
            fs_store.join("monitor_updates").join("chan-a").join("1"),
            b"update-1",
        )
        .unwrap();

        let scb_path = tmp.path().join("scb.bin");
        write_monitor_store_scb(tmp.path(), &scb_path).unwrap();
        let blob = fs::read(scb_path).unwrap();

        assert!(blob.starts_with(SCB_BLOB_MAGIC));
        assert!(contains(&blob, b"monitors"));
        assert!(contains(&blob, b"monitor_updates"));
        assert!(contains(&blob, b"manager"));
        assert!(contains(&blob, b"monitor-bytes"));
        assert!(contains(&blob, b"update-1"));
        assert!(contains(&blob, b"manager-bytes"));
    }
}
