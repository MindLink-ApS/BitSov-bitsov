//! Local disk admission and data-generation guards.
use anyhow::{Context, Result};
use konsensus_core::traits::lightning::{DiskStatus, LightningError};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::watch;

/// Monotonic binary/state compatibility generation. Bump BEFORE shipping any
/// incompatible SQLite migration or LDK state change; never derive from SemVer.
pub const STATE_GENERATION: u64 = 1;

pub struct DiskGuard {
    path: PathBuf,
    floor: u64,
    state: RwLock<DiskStatus>,
}

fn disk_status(free: io::Result<u64>, floor: u64) -> DiskStatus {
    let free = free.ok();
    DiskStatus {
        disk_low: free.is_none_or(|n| n < floor),
        disk_free_bytes: free,
        disk_free_floor_bytes: floor,
    }
}

impl DiskGuard {
    pub fn new(path: PathBuf, floor: u64) -> Self {
        let state = RwLock::new(disk_status(available_space(&path), floor));
        Self { path, floor, state }
    }

    pub fn refresh(&self) -> DiskStatus {
        let next = disk_status(available_space(&self.path), self.floor);
        let mut state = self.state.write().unwrap();
        if state.disk_low != next.disk_low {
            tracing::warn!(disk_low = next.disk_low, free_bytes = ?next.disk_free_bytes, floor_bytes = self.floor, "disk admission changed");
        }
        *state = next;
        next
    }

    pub fn check(&self) -> Result<(), LightningError> {
        if self.refresh().disk_low {
            Err(LightningError::PaymentNotDispatched("disk_low".into()))
        } else {
            Ok(())
        }
    }

    pub async fn monitor(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = tick.tick() => { self.refresh(); }
            }
        }
    }
}

#[cfg(unix)]
fn available_space(path: &Path) -> io::Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in data directory"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated; stat points to writable, correctly sized
    // storage. Only read it after statvfs reports successful initialization.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    // f_bavail excludes blocks reserved for root (f_bfree does not).
    Ok((u128::from(stat.f_bavail) * u128::from(stat.f_frsize)).min(u128::from(u64::MAX)) as u64)
}

#[cfg(not(unix))]
fn available_space(_path: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "disk probe requires Unix",
    ))
}

/// Persist the high-water mark before any storage migration or LDK construction.
/// A whole-directory restore also restores this marker: it is NOT backup freshness proof.
pub fn ensure_generation(dir: &Path, generation: u64) -> Result<File> {
    let result = (|| -> Result<File> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("STATE_GENERATION.lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the fd remains owned by lock until this function returns.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                anyhow::bail!("state_generation_busy: {}", io::Error::last_os_error());
            }
        }
        let path = dir.join("STATE_GENERATION");
        match fs::read_to_string(&path) {
            Ok(text) => {
                let previous: u64 = text
                    .trim()
                    .strip_prefix("bitsov-state-v1:")
                    .context("state_generation_invalid")?
                    .parse()
                    .context("state_generation_invalid")?;
                if previous > generation {
                    anyhow::bail!("state_generation_newer: data generation {previous}, binary supports {generation}");
                }
                if previous == generation {
                    // A prior failed directory fsync may have left a visible
                    // but non-durable rename. Re-establish durability before use.
                    File::open(&path)?.sync_all()?;
                    File::open(dir)?.sync_all()?;
                    return Ok(lock);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let temp = dir.join(format!(".STATE_GENERATION.{}", uuid::Uuid::new_v4()));
        let write = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            writeln!(file, "bitsov-state-v1:{generation}")?;
            file.sync_all()?;
            fs::rename(&temp, &path)?;
            File::open(dir)?.sync_all()?;
            Ok(())
        })();
        if write.is_err() {
            let _ = fs::remove_file(temp);
        }
        write?;
        // The caller retains this lease until every state user has stopped.
        Ok(lock)
    })();
    result.map_err(|e| anyhow::anyhow!("{e:#}; refusing state startup. See docs/UPGRADING.md; do not restore an old live LDK directory."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_floor_boundary_and_probe_failure() {
        assert!(!disk_status(Ok(2_147_483_648), 2_147_483_648).disk_low);
        assert!(disk_status(Ok(2_147_483_647), 2_147_483_648).disk_low);
        let failed = disk_status(Err(std::io::Error::other("probe failed")), 0);
        assert!(failed.disk_low);
        assert_eq!(failed.disk_free_bytes, None);
    }

    #[test]
    fn generation_lease_prevents_concurrent_state_users() {
        let dir = tempfile::tempdir().unwrap();
        let lease = ensure_generation(dir.path(), 1).unwrap();
        let error = ensure_generation(dir.path(), 2).unwrap_err().to_string();
        assert!(error.contains("state_generation_busy"));
        drop(lease);
        ensure_generation(dir.path(), 2).unwrap();
    }

    #[test]
    fn generation_is_monotonic_and_rejects_downgrade_or_corruption() {
        let dir = tempfile::tempdir().unwrap();
        ensure_generation(dir.path(), 1).unwrap();
        ensure_generation(dir.path(), 2).unwrap();
        let path = dir.path().join("STATE_GENERATION");
        let before = std::fs::read(&path).unwrap();
        let err = ensure_generation(dir.path(), 1).unwrap_err().to_string();
        assert!(err.contains("state_generation_newer"));
        assert!(err.contains("docs/UPGRADING.md"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        ensure_generation(dir.path(), 2).unwrap();
        std::fs::write(&path, "broken").unwrap();
        assert!(ensure_generation(dir.path(), 2).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "broken");
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_probe_fails_closed_and_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let guard = std::sync::Arc::new(DiskGuard::new(dir.path().into(), 0));
        assert!(!guard.state.read().unwrap().disk_low);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(guard.clone().monitor(rx));
        tokio::task::yield_now().await;
        std::fs::remove_dir(dir.path()).unwrap();
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(guard.state.read().unwrap().disk_low);
        std::fs::create_dir(dir.path()).unwrap();
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(!guard.state.read().unwrap().disk_low);
        tx.send(true).unwrap();
        task.await.unwrap();
    }
}
