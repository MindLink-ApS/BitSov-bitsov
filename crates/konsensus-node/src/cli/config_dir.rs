//! The config's directory, opened once and used by handle for every file
//! `chain-tip` reads back or writes.
//!
//! Path checks alone are not enough: each later open, link or rename would
//! resolve the path again, and a changed symlink in a parent could send the
//! write somewhere else. Here the directory is opened once, checked (owned by
//! this user, not writable by group or others), and every later step names a
//! file *inside that open directory*: a parent changed afterwards no longer
//! matters. Files this command creates are removed only while the name still
//! points at the file it created.
#![cfg(unix)]

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, Result};

/// `(device, inode)` of a file system object.
pub(crate) type FileId = (u64, u64);

pub(crate) struct ConfigDir {
    dir: OwnedFd,
    id: FileId,
}

fn cstr(name: &OsStr) -> std::io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

fn check(rc: libc::c_int) -> std::io::Result<()> {
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// The field types differ by platform (st_dev is i32 on macOS, u64 on Linux).
#[allow(clippy::unnecessary_cast)]
fn stat_id(st: &libc::stat) -> FileId {
    (st.st_dev as u64, st.st_ino as u64)
}

impl ConfigDir {
    /// Open the directory that holds `config`. Refused unless it is a directory
    /// owned by the current user that neither group nor others can write.
    pub(crate) fn open(config: &Path) -> Result<Self> {
        let parent = config
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = cstr(parent.as_os_str())?;
        // SAFETY: path is a valid NUL-terminated string; the result is checked.
        let fd = unsafe {
            libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(anyhow!(
                "could not open {} ({})",
                parent.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fd was just returned by open and is owned here.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: dir is open; st is a valid out-pointer.
        check(unsafe { libc::fstat(dir.as_raw_fd(), &mut st) })?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if st.st_uid != me {
            return Err(anyhow!(
                "{} belongs to another user; the config directory must be your own",
                parent.display()
            ));
        }
        if (st.st_mode as u32) & 0o022 != 0 {
            return Err(anyhow!(
                "{} can be written by other users; make it private (chmod go-w) first",
                parent.display()
            ));
        }
        Ok(Self { dir, id: stat_id(&st) })
    }

    pub(crate) fn id(&self) -> FileId {
        self.id
    }

    /// The object `name` in this directory, without following a final symlink.
    pub(crate) fn entry_id(&self, name: &OsStr) -> std::io::Result<Option<FileId>> {
        let name = cstr(name)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd, NUL-terminated name, valid out-pointer.
        let rc = unsafe {
            libc::fstatat(self.dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
        };
        if rc == -1 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::NotFound { Ok(None) } else { Err(e) };
        }
        Ok(Some(stat_id(&st)))
    }

    /// Read `name` from this directory. A symlink at `name` is refused.
    pub(crate) fn read(&self, name: &OsStr) -> std::io::Result<Vec<u8>> {
        let mut file = self.open_at(name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn open_at(&self, name: &OsStr, flags: libc::c_int, mode: libc::c_uint) -> std::io::Result<File> {
        let name = cstr(name)?;
        // SAFETY: valid fd and NUL-terminated name; the result is checked.
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd was just returned by openat and is owned by the File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Create `name` (which must not exist), write `bytes`, fsync. Mode 0600.
    /// Returns the created file's id, so cleanup can tell it from a replacement.
    pub(crate) fn create_new(&self, name: &OsStr, bytes: &[u8]) -> std::io::Result<FileId> {
        let mut file = self.open_at(
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the file is open; st is a valid out-pointer.
        check(unsafe { libc::fstat(file.as_raw_fd(), &mut st) })?;
        let id = stat_id(&st);
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        if let Err(e) = written {
            drop(file);
            self.remove_if(name, id);
            return Err(e);
        }
        Ok(id)
    }

    /// Hard-link `from` to `to` inside this directory; fails if `to` exists.
    pub(crate) fn link(&self, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        let (from, to) = (cstr(from)?, cstr(to)?);
        let fd = self.dir.as_raw_fd();
        // SAFETY: valid fd and NUL-terminated names.
        check(unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) })
    }

    /// Atomically rename `from` over `to`, both inside this directory.
    pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        let (from, to) = (cstr(from)?, cstr(to)?);
        let fd = self.dir.as_raw_fd();
        // SAFETY: valid fd and NUL-terminated names.
        check(unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) })
    }

    /// Remove `name` only while it is still the file this operation created.
    pub(crate) fn remove_if(&self, name: &OsStr, created: FileId) {
        if matches!(self.entry_id(name), Ok(Some(id)) if id == created) {
            if let Ok(name) = cstr(name) {
                // SAFETY: valid fd and NUL-terminated name.
                let _ = unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
            }
        }
    }

    pub(crate) fn sync(&self) -> std::io::Result<()> {
        // SAFETY: the directory fd is open.
        check(unsafe { libc::fsync(self.dir.as_raw_fd()) })
    }
}

/// `(device, inode)` of `path`, following symlinks; `None` if it does not exist.
pub(crate) fn path_id(path: &Path) -> std::io::Result<Option<FileId>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some((m.dev(), m.ino()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
