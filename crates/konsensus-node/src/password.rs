//! One-shot seed-password handoff. Never include input bytes in diagnostics.

use std::io::{self, Read};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Read a UTF-8 password to EOF, stripping trailing CR/LF only. The fixed
/// zeroizing buffer avoids leaving secret copies in reallocated buffers.
fn read_password(mut reader: impl Read) -> Result<Zeroizing<String>> {
    const MAX_BYTES: usize = 4096;
    let mut bytes = Zeroizing::new([0u8; MAX_BYTES + 1]);
    let mut len = 0;
    loop {
        match reader.read(&mut bytes[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                anyhow::ensure!(len <= MAX_BYTES, "password exceeds 4096 bytes");
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("cannot read password descriptor"),
        }
    }
    let password = std::str::from_utf8(&bytes[..len])
        .context("password must be valid UTF-8")?
        .trim_end_matches(['\r', '\n']);
    anyhow::ensure!(!password.is_empty(), "password descriptor is empty");
    Ok(Zeroizing::new(password.to_owned()))
}

/// Borrow an inherited descriptor (0 = stdin), consuming it to EOF exactly
/// once. Duplicate it with CLOEXEC so only the duplicate is owned/closed here;
/// the caller's descriptor remains open, with its read position advanced.
/// Invalid descriptor numbers must be checked by the OS, never turned directly
/// into a BorrowedFd/OwnedFd (which would violate their safety requirements).
pub fn read_password_fd(fd: i32) -> Result<Zeroizing<String>> {
    anyhow::ensure!(fd >= 0, "password descriptor must be non-negative");
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        // SAFETY: fcntl validates fd, returns a new descriptor on success, and
        // neither accesses Rust memory nor transfers ownership of the input.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate == -1 {
            return Err(io::Error::last_os_error()).context("cannot read password descriptor");
        }
        // SAFETY: duplicate is a newly opened, valid descriptor owned by us.
        let file = unsafe { std::fs::File::from_raw_fd(duplicate) };
        read_password(file)
    }
    #[cfg(not(unix))]
    {
        anyhow::ensure!(
            fd == 0,
            "only password descriptor 0 (stdin) is supported on this platform"
        );
        read_password(io::stdin().lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_spaces_unicode_and_interior_newlines() {
        let password = read_password(&b"  s\xc3\xa9cret\npass  \r\n"[..]).unwrap();
        assert_eq!(password.as_str(), "  sécret\npass  ");
        assert_eq!(
            read_password(&b"no-newline"[..]).unwrap().as_str(),
            "no-newline"
        );
    }

    #[test]
    fn rejects_empty_non_utf8_and_over_limit_without_echoing_input() {
        for bytes in [vec![], b"\r\n".to_vec(), vec![0xff], vec![b'x'; 4097]] {
            assert!(read_password(bytes.as_slice()).is_err());
        }
        assert_eq!(read_password(&vec![b'x'; 4096][..]).unwrap().len(), 4096);
    }

    #[cfg(unix)]
    #[test]
    fn consumes_descriptor_once_without_taking_ownership() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.write_all(b"one-shot-password\n").unwrap();
        drop(writer);
        assert_eq!(
            read_password_fd(reader.as_raw_fd()).unwrap().as_str(),
            "one-shot-password"
        );
        let mut byte = [0];
        assert_eq!(
            reader.read(&mut byte).unwrap(),
            0,
            "original stays open at EOF"
        );
        assert!(
            read_password_fd(reader.as_raw_fd()).is_err(),
            "no cached second read"
        );
    }
}
