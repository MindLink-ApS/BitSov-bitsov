//! Host/volume admission fence. This is not a channel-state freshness proof.
//!
//! Callers hold STATE_GENERATION.lock across admission and all state use.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, Write},
    path::Path,
};

#[path = "restore_fence/host.rs"]
mod host;

const GUIDANCE: &str = "refusing state startup: this may be a restored copy. run konsensus recover in a fresh directory; see docs/v2/RECOVERY.md and docs/operations/home-node.md. Never start an old copied data directory";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    version: u32,
    instance_id: uuid::Uuid,
    binding: String,
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            anyhow::ensure!(
                meta.file_type().is_file(),
                "{} must be a regular file",
                path.display()
            );
            Ok(Some(fs::read(path).with_context(|| {
                format!("cannot read {}", path.display())
            })?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn ensure_no_recovery(dir: &Path) -> Result<()> {
    konsensus_lightning::recover::ensure_normal_start(dir).map_err(anyhow::Error::msg)
}

fn load_instance(dir: &Path) -> Result<Option<Instance>> {
    let Some(bytes) = read_optional(&dir.join("INSTANCE"))? else {
        return Ok(None);
    };
    let record: Instance = serde_json::from_slice(&bytes).context("INSTANCE invalid")?;
    anyhow::ensure!(
        record.version == 1
            && !record.instance_id.is_nil()
            && record.binding.len() == 64
            && record.binding.bytes().all(|b| b.is_ascii_hexdigit()),
        "INSTANCE invalid or unsupported"
    );
    Ok(Some(record))
}

fn binding(machine: &str, volume: &str, id: uuid::Uuid) -> Result<String> {
    anyhow::ensure!(!machine.trim().is_empty() && !volume.trim().is_empty(),
        "host_binding_unavailable: machine or filesystem identity missing; fix platform identity provisioning; {GUIDANCE}");
    // Domain separation and length prefixes prevent ambiguous concatenations.
    let mut hash = blake3::Hasher::new();
    hash.update(b"bitsov-instance-v1");
    for part in [machine.as_bytes(), volume.as_bytes(), id.as_bytes()] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(hash.finalize().to_hex().to_string())
}

fn persist(dir: &Path, record: &Instance) -> Result<()> {
    let temp = dir.join(format!(".INSTANCE.{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp, dir.join("INSTANCE"))?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.context("cannot durably persist INSTANCE")
}

fn admit(dir: &Path, machine: &str, volume: &str) -> Result<()> {
    ensure_no_recovery(dir)?;
    match load_instance(dir)? {
        Some(record) => {
            anyhow::ensure!(record.binding == binding(machine, volume, record.instance_id)?,
                "host_binding_mismatch: machine or filesystem changed; {GUIDANCE}. For a legitimate latest-live-store move only, see the documented konsensus rebind-instance console override");
            // Re-establish durability after a prior failed directory fsync.
            File::open(dir.join("INSTANCE"))?.sync_all()?;
            File::open(dir)?.sync_all()?;
            Ok(())
        }
        None => {
            let instance_id = uuid::Uuid::new_v4();
            persist(
                dir,
                &Instance {
                    version: 1,
                    instance_id,
                    binding: binding(machine, volume, instance_id)?,
                },
            )
        }
    }
}

/// Bind on first init/upgrade, otherwise verify before any LDK construction.
pub fn ensure_bound(data_dir: &Path) -> Result<()> {
    let result = (|| -> Result<()> {
        let dir = data_dir.join("ldk");
        fs::create_dir_all(&dir)?;
        File::open(data_dir)?.sync_all()?;
        ensure_no_recovery(&dir)?;
        let (machine, volume) = host::identity(&dir).context("host_binding_unavailable: cannot obtain machine/filesystem identity; fix OS identity provisioning (Linux needs a persistent machine-id); no bypass is available")?;
        admit(&dir, &machine, &volume)
    })();
    result.with_context(|| GUIDANCE)
}

/// Verify the host binding while the recovery journal deliberately remains open.
/// The command holds the root process lease and refuses any existing LDK store.
pub fn ensure_recovery_bound(data_dir: &Path) -> Result<()> {
    let dir = data_dir.join("ldk");
    konsensus_lightning::recover::ensure_recovery_root(&dir).map_err(anyhow::Error::msg)?;
    let (machine, volume) = host::identity(&dir)?;
    match load_instance(&dir)? {
        Some(record) => anyhow::ensure!(
            record.binding == binding(&machine, &volume, record.instance_id)?,
            "host_binding_mismatch; use a fresh recovery directory"
        ),
        None => {
            let instance_id = uuid::Uuid::new_v4();
            persist(
                &dir,
                &Instance {
                    version: 1,
                    instance_id,
                    binding: binding(&machine, &volume, instance_id)?,
                },
            )?;
        }
    }
    Ok(())
}

fn rebind(
    dir: &Path,
    machine: &str,
    volume: &str,
    confirm: impl FnOnce(&str) -> Result<String>,
) -> Result<()> {
    ensure_no_recovery(dir)?;
    let mut record = load_instance(dir)?
        .context("no INSTANCE to rebind; an existing node binds on first start")?;
    let new_binding = binding(machine, volume, record.instance_id)?;
    let challenge = format!("REBIND {} TO {}", record.instance_id, new_binding);
    anyhow::ensure!(
        confirm(&challenge)? == challenge,
        "owner confirmation did not match; INSTANCE unchanged"
    );
    record.binding = new_binding;
    persist(dir, &record)
}

/// Separate owner-console operation: never constructs or starts LDK.
pub fn rebind_instance(config_path: &Path) -> Result<()> {
    let config = crate::config::NodeConfig::load(config_path)?;
    let data_dir = config
        .identity
        .mnemonic_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let _lease = crate::safety::ensure_generation(data_dir, crate::safety::STATE_GENERATION)?;
    let dir = data_dir.join("ldk");
    konsensus_lightning::ldk::ensure_no_move_home(&dir)?;
    ensure_no_recovery(&dir)?;
    let (machine, volume) = host::identity(&dir)
        .context("host_binding_unavailable; fix OS identity provisioning before rebinding")?;
    rebind(&dir, &machine, &volume, |challenge| {
        let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")
            .context("rebind-instance requires the owner's controlling console (/dev/tty); stdin and flags cannot confirm")?;
        writeln!(tty, "WARNING: This does not prove state freshness. Only rebind the latest cleanly stopped live store after disabling the old node. Never rebind a backup or snapshot: stale commitments can lose the entire channel balance. See docs/operations/home-node.md.\nDirectory: {}\nType exactly to authorize:\n{challenge}", fs::canonicalize(&dir)?.display())?;
        tty.flush()?;
        let mut response = String::new();
        std::io::BufReader::new(&tty).read_line(&mut response)?;
        Ok(response.trim_end_matches(['\r', '\n']).to_owned())
    })?;
    println!("Instance rebound. No node was started. Keep the old node disabled.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fresh_init_and_upgrade_bind_and_remain_stable() {
        for existing in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            if existing {
                fs::write(dir.path().join("ldk_node_data.sqlite"), b"retained state").unwrap();
            }
            admit(dir.path(), "host-a", "volume-a").unwrap();
            let record = fs::read(dir.path().join("INSTANCE")).unwrap();
            admit(dir.path(), "host-a", "volume-a").unwrap();
            assert_eq!(fs::read(dir.path().join("INSTANCE")).unwrap(), record);
        }
    }

    #[test]
    fn copied_dir_refuses_changed_host_or_volume_without_rewriting() {
        let original = tempfile::tempdir().unwrap();
        let copy = tempfile::tempdir().unwrap();
        admit(original.path(), "host-a", "volume-a").unwrap();
        fs::copy(
            original.path().join("INSTANCE"),
            copy.path().join("INSTANCE"),
        )
        .unwrap();
        let before = fs::read(copy.path().join("INSTANCE")).unwrap();
        for (host, volume) in [("host-b", "volume-a"), ("host-a", "volume-b")] {
            let err = admit(copy.path(), host, volume).unwrap_err().to_string();
            assert!(err.contains("konsensus recover"));
            assert!(err.contains("fresh directory"));
            assert_eq!(fs::read(copy.path().join("INSTANCE")).unwrap(), before);
        }
    }

    #[test]
    fn recovery_journal_open_unknown_or_corrupt_refuses_even_override() {
        for json in [
            r#"{"version":1,"state":"open"}"#,
            r#"{"version":2,"state":"done"}"#,
            r#"{"version":1,"state":"sweeping"}"#,
            "{}",
            "broken",
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("recover.json"), json).unwrap();
            assert!(admit(dir.path(), "host-a", "volume-a").is_err(), "{json}");
            assert!(rebind(dir.path(), "host-b", "volume-a", |_| panic!(
                "must not prompt"
            ))
            .is_err());
            assert!(!dir.path().join("INSTANCE").exists());
        }
    }

    #[test]
    fn completed_recovery_journal_allows_start() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("recover.json"),
            r#"{"version":1,"state":"done"}"#,
        )
        .unwrap();
        admit(dir.path(), "host-a", "volume-a").unwrap();
    }

    #[test]
    fn override_requires_exact_confirmation_and_preserves_instance_id() {
        let dir = tempfile::tempdir().unwrap();
        admit(dir.path(), "host-a", "volume-a").unwrap();
        let before = fs::read(dir.path().join("INSTANCE")).unwrap();
        for response in ["", "yes", "REBIND", " REBIND"] {
            assert!(rebind(dir.path(), "host-b", "volume-a", |_| Ok(response.into())).is_err());
            assert_eq!(fs::read(dir.path().join("INSTANCE")).unwrap(), before);
        }
        assert!(rebind(dir.path(), "host-b", "volume-a", |_| anyhow::bail!(
            "no console"
        ))
        .is_err());
        assert_eq!(fs::read(dir.path().join("INSTANCE")).unwrap(), before);
        rebind(dir.path(), "host-b", "volume-a", |challenge| {
            Ok(challenge.into())
        })
        .unwrap();
        admit(dir.path(), "host-b", "volume-a").unwrap();
        assert!(admit(dir.path(), "host-a", "volume-a").is_err());
        let old: serde_json::Value = serde_json::from_slice(&before).unwrap();
        let new: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("INSTANCE")).unwrap()).unwrap();
        assert_eq!(old["instance_id"], new["instance_id"]);
    }

    #[test]
    fn unavailable_identity_and_corrupt_binding_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(admit(dir.path(), "", "volume").is_err());
        assert!(admit(dir.path(), "host", "").is_err());
        assert!(!dir.path().join("INSTANCE").exists());
        fs::write(dir.path().join("INSTANCE"), "broken").unwrap();
        assert!(admit(dir.path(), "host", "volume").is_err());
        assert!(rebind(dir.path(), "host", "volume", |s| Ok(s.into())).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join("INSTANCE")).unwrap(),
            "broken"
        );
    }
}
