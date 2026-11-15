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

/// Whether a password descriptor is protected from other OS users.
///
/// A redirected file (`--password-fd 3 3<pw`) or FIFO must pass the same
/// ownership/mode rule as `--password-file`. On Linux and macOS, a socket must
/// be a connected AF_UNIX stream with a peer UID equal to getuid(). Socket mode
/// bits are not used. Unsupported types, invalid descriptors, and platforms
/// without Unix modes return false.
pub fn descriptor_is_owner_only(fd: i32) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if fd < 0 {
            return false;
        }
        // SAFETY: as in `read_password_fd`: fcntl validates fd and returns a new
        // descriptor on success, without taking ownership of the input.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate == -1 {
            return false;
        }
        // SAFETY: duplicate is a newly opened, valid descriptor owned by us.
        let file = unsafe { std::fs::File::from_raw_fd(duplicate) };
        let Ok(meta) = file.metadata() else {
            return false;
        };
        let file_type = meta.file_type();
        if file_type.is_socket() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                use std::os::fd::AsRawFd;

                let socket = socket2::SockRef::from(&file);
                if socket.r#type().ok() != Some(socket2::Type::STREAM)
                    || !socket.peer_addr().is_ok_and(|peer| peer.is_unix())
                {
                    return false;
                }
                #[cfg(target_os = "linux")]
                {
                    let mut credentials = libc::ucred {
                        pid: 0,
                        uid: 0,
                        gid: 0,
                    };
                    let mut len = std::mem::size_of_val(&credentials) as libc::socklen_t;
                    // SAFETY: file owns a valid socket descriptor; credentials
                    // and len are writable and sized for SO_PEERCRED.
                    let status = unsafe {
                        libc::getsockopt(
                            file.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_PEERCRED,
                            (&mut credentials as *mut libc::ucred).cast(),
                            &mut len,
                        )
                    };
                    return status == 0
                        && len as usize == std::mem::size_of_val(&credentials)
                        // SAFETY: getuid has no preconditions and cannot fail.
                        && credentials.uid == unsafe { libc::getuid() };
                }
                #[cfg(target_os = "macos")]
                {
                    let mut peer_uid = 0;
                    let mut peer_gid = 0;
                    // SAFETY: file owns a valid socket descriptor; the output
                    // pointers reference writable uid_t and gid_t values.
                    let status =
                        unsafe { libc::getpeereid(file.as_raw_fd(), &mut peer_uid, &mut peer_gid) };
                    return status == 0
                        // SAFETY: getuid has no preconditions and cannot fail.
                        && peer_uid == unsafe { libc::getuid() };
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            return false;
        }
        (file_type.is_file() || file_type.is_fifo())
            && meta.mode() & 0o077 == 0
            // SAFETY: getuid has no preconditions and cannot fail.
            && meta.uid() == unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_same_uid_unix_stream_socketpair_is_owner_only() {
        use std::os::fd::AsRawFd;

        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(descriptor_is_owner_only(reader.as_raw_fd()));
        assert!(descriptor_is_owner_only(writer.as_raw_fd()));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_same_uid_unix_stream_connection_is_owner_only() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(descriptor_is_owner_only(client.as_raw_fd()));
        assert!(descriptor_is_owner_only(server.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn connected_inet_stream_sockets_are_not_owner_only() {
        use std::net::{Ipv4Addr, TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(!descriptor_is_owner_only(client.as_raw_fd()));
        assert!(!descriptor_is_owner_only(server.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn connected_inet6_stream_sockets_are_not_owner_only() {
        use std::net::{Ipv6Addr, TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(!descriptor_is_owner_only(client.as_raw_fd()));
        assert!(!descriptor_is_owner_only(server.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn a_listening_unix_stream_socket_is_not_owner_only() {
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join("input.sock")).unwrap();
        assert!(!descriptor_is_owner_only(listener.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn a_connected_unix_datagram_socket_is_not_owner_only() {
        use std::os::fd::AsRawFd;

        let (reader, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(!descriptor_is_owner_only(reader.as_raw_fd()));
        assert!(!descriptor_is_owner_only(writer.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn an_unconnected_unix_stream_socket_is_not_owner_only() {
        use std::os::fd::AsRawFd;

        let socket =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        assert!(!descriptor_is_owner_only(socket.as_raw_fd()));
    }

    #[cfg(unix)]
    #[test]
    fn a_redirected_file_must_be_owner_only_and_a_connected_unix_stream_qualifies() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "secret").unwrap();
        for (mode, owner_only) in [(0o600, true), (0o400, true), (0o640, false), (0o604, false)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            assert_eq!(
                descriptor_is_owner_only(file.as_raw_fd()),
                owner_only,
                "{mode:o}"
            );
        }
        let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(descriptor_is_owner_only(reader.as_raw_fd()));
        assert!(!descriptor_is_owner_only(2147483647));
        assert!(!descriptor_is_owner_only(-1));
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_descriptor_must_be_owner_only() {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw-fifo");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        for (mode, owner_only) in [(0o600, true), (0o666, false)] {
            // Set the exact mode independently of the process umask.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                descriptor_is_owner_only(reader.as_raw_fd()),
                owner_only,
                "{mode:o}"
            );
        }
    }

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
