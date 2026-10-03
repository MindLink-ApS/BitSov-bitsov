//! Shared size-bounded file output for node and embedded LDK diagnostics.
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU64, NonZeroUsize};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Limits apply independently to each log, including the active file.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub max_file_size_bytes: NonZeroU64,
    pub max_files: NonZeroUsize,
}
impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: NonZeroU64::new(10 * 1024 * 1024).unwrap(),
            max_files: NonZeroUsize::new(5).unwrap(),
        }
    }
}

/// A synchronous writer. Clone this handle to share the rotation lock across
/// threads; only one independently opened writer may own a given path.
/// Ordinary writes stay together; writes larger than the cap are split.
#[derive(Clone)]
pub struct RotatingLog {
    path: PathBuf,
    config: LoggingConfig,
    lock: Arc<Mutex<()>>,
}
impl RotatingLog {
    pub fn open(path: impl AsRef<Path>, config: LoggingConfig) -> io::Result<Self> {
        let log = Self {
            path: path.as_ref().to_owned(),
            config,
            lock: Arc::new(Mutex::new(())),
        };
        // Normalize existing logs on restart, including after lowering limits.
        // Only canonical numeric archive suffixes belong to this writer.
        let parent = log
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = log.path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "log path needs a filename")
        })?;
        let prefix = format!("{}.", name.to_string_lossy());
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(suffix) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
                continue;
            };
            let Ok(index) = suffix.parse::<usize>() else {
                continue;
            };
            if index == 0 || index.to_string() != suffix {
                continue;
            }
            if index >= config.max_files.get() {
                std::fs::remove_file(entry.path())?;
            } else {
                Self::bound_existing(&entry.path(), config.max_file_size_bytes.get())?;
            }
        }
        log.append_file()?;
        Self::bound_existing(&log.path, config.max_file_size_bytes.get())?;
        Ok(log)
    }

    fn append_file(&self) -> io::Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.path)
    }

    // Keep the newest bytes of an oversized legacy log without allocating in
    // proportion to its size (the old VM logs may already be many gigabytes).
    fn bound_existing(path: &Path, cap: u64) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        if len <= cap {
            return Ok(());
        }
        let mut buffer = [0u8; 8192];
        let mut offset = 0;
        while offset < cap {
            let count = (cap - offset).min(buffer.len() as u64) as usize;
            file.seek(SeekFrom::Start(len - cap + offset))?;
            file.read_exact(&mut buffer[..count])?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&buffer[..count])?;
            offset += count as u64;
        }
        file.set_len(cap)
    }

    fn archive(&self, index: usize) -> PathBuf {
        if index == 0 {
            return self.path.clone();
        }
        let mut path = self.path.as_os_str().to_owned();
        path.push(format!(".{index}"));
        PathBuf::from(path)
    }

    fn rotate(&self) -> io::Result<()> {
        let last = self.config.max_files.get() - 1;
        match std::fs::remove_file(self.archive(last)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for index in (1..=last).rev() {
            match std::fs::rename(self.archive(index - 1), self.archive(index)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
impl Write for RotatingLog {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let _lock = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        let total = buf.len();
        let cap = self.config.max_file_size_bytes.get();
        while !buf.is_empty() {
            let mut file = self.append_file()?;
            let len = file.metadata()?.len();
            // Rotate before the write, preserving normal records intact.
            if len > 0 && (len >= cap || buf.len() as u64 > cap - len) {
                drop(file); // Close before rename, including on Windows.
                self.rotate()?;
                file = self.append_file()?;
            }
            let count = (buf.len() as u64).min(cap) as usize;
            file.write_all(&buf[..count])?;
            buf = &buf[count..];
        }
        Ok(total)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    } // No userspace buffering.
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(size: u64, count: usize) -> LoggingConfig {
        LoggingConfig {
            max_file_size_bytes: size.try_into().unwrap(),
            max_files: count.try_into().unwrap(),
        }
    }
    fn assert_bounded(dir: &Path, size: u64, count: usize) {
        let sizes: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .collect();
        assert!(sizes.len() <= count, "too many files: {sizes:?}");
        assert!(
            sizes.iter().all(|len| *len <= size),
            "oversized file: {sizes:?}"
        );
        assert!(sizes.iter().sum::<u64>() <= size * count as u64);
    }
    #[test]
    fn writing_past_cap_rotates_and_total_size_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.log");
        let mut log = RotatingLog::open(&path, config(16, 3)).unwrap();
        for n in 0..20 {
            log.write_all(format!("record-{n:08}\n").as_bytes())
                .unwrap();
            assert_bounded(dir.path(), 16, 3);
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "record-00000019\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("node.log.1")).unwrap(),
            "record-00000018\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("node.log.2")).unwrap(),
            "record-00000017\n"
        );
    }
    #[test]
    fn oversized_writes_and_single_file_retention_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path().join("node.log"), config(16, 1)).unwrap();
        log.write_all(&[b'x'; 1000]).unwrap();
        assert_bounded(dir.path(), 16, 1);
    }
    #[test]
    fn reopening_prunes_old_archives_and_bounds_legacy_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.log");
        std::fs::write(&path, [b'x'; 1000]).unwrap();
        std::fs::write(dir.path().join("node.log.1"), [b'y'; 1000]).unwrap();
        std::fs::write(dir.path().join("node.log.5"), [b'z'; 1000]).unwrap();
        let mut log = RotatingLog::open(&path, config(16, 2)).unwrap();
        assert_bounded(dir.path(), 16, 2);
        log.write_all(b"new\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
        assert_bounded(dir.path(), 16, 2);
    }
    #[test]
    fn concurrent_clones_share_rotation_state() {
        let dir = tempfile::tempdir().unwrap();
        let log = RotatingLog::open(dir.path().join("node.log"), config(16, 3)).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let mut log = log.clone();
                scope.spawn(move || {
                    for _ in 0..100 {
                        log.write_all(b"123456789abcdef\n").unwrap();
                    }
                });
            }
        });
        assert_bounded(dir.path(), 16, 3);
    }
}

#[cfg(test)]
mod restart_and_failure_tests {
    use super::*;
    #[test]
    fn restart_preserves_latest_bytes_and_resumes_below_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.log");
        let bytes: Vec<u8> = (0..20003).map(|n| (n % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let config = LoggingConfig {
            max_file_size_bytes: 10000.try_into().unwrap(),
            max_files: 2.try_into().unwrap(),
        };
        drop(RotatingLog::open(&path, config).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), bytes[10003..]);
        std::fs::write(&path, b"before\n").unwrap();
        let mut log = RotatingLog::open(&path, config).unwrap();
        log.write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"before\nafter\n");
    }
    #[test]
    fn rotation_failure_does_not_append_past_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.log");
        let config = LoggingConfig {
            max_file_size_bytes: 4.try_into().unwrap(),
            max_files: 2.try_into().unwrap(),
        };
        let mut log = RotatingLog::open(&path, config).unwrap();
        log.write_all(b"full").unwrap();
        std::fs::create_dir(dir.path().join("node.log.1")).unwrap();
        assert!(log.write_all(b"next").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"full");
    }
}
