use super::*;

#[test]
fn encrypt_decrypt_roundtrip() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "test-password-123";

    let encrypted = encrypt_mnemonic(mnemonic, password).unwrap();
    assert!(encrypted.len() > HEADER_LEN);
    assert_eq!(encrypted[0], FORMAT_VERSION);

    let decrypted: Zeroizing<String> = decrypt_mnemonic(&encrypted, password).unwrap();
    assert_eq!(decrypted.as_str(), mnemonic);
}

#[test]
fn non_utf8_plaintext_is_not_retained_in_error() {
    // Authenticated legacy ciphertext containing synthetic, non-UTF-8 data.
    let plaintext = b"synthetic-secret-marker\xff";
    let password = "legacy-test-password";
    let salt = [7; SALT_LEN];
    let nonce = [9; NONCE_LEN];
    let key = derive_key(password.as_bytes(), &salt).unwrap();
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .unwrap();
    let mut encrypted = vec![FORMAT_VERSION];
    encrypted.extend_from_slice(&salt);
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    let error = decrypt_mnemonic(&encrypted, password).unwrap_err();
    assert!(matches!(&error, MnemonicCryptoError::InvalidFormat(message)
        if message == "decrypted data is not valid UTF-8"));
    assert!(!error.to_string().contains("synthetic-secret-marker"));
    assert!(!format!("{error:?}").contains("synthetic-secret-marker"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn wrong_password_fails() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let encrypted = encrypt_mnemonic(mnemonic, "correct").unwrap();
    let result = decrypt_mnemonic(&encrypted, "wrong");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MnemonicCryptoError::Decryption
    ));
}

#[test]
fn blank_encryption_passwords_are_rejected() {
    for password in ["", "   ", "\t\r\n", "\u{2003}\u{a0}"] {
        let error = encrypt_mnemonic("test phrase", password).unwrap_err();
        assert!(error
            .to_string()
            .contains("must not be empty or whitespace-only"));
    }
}

#[test]
fn blank_password_writes_nothing_and_preserves_existing_files() {
    for password in ["", "   ", "\t\r\n", "\u{2003}\u{a0}"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnemonic.txt");
        assert!(write_mnemonic(&path, "test phrase", Some(password)).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        std::fs::write(&path, b"existing plaintext").unwrap();
        let encrypted = path.with_extension("enc");
        std::fs::write(&encrypted, b"existing ciphertext").unwrap();
        assert!(write_mnemonic(&path, "test phrase", Some(password)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing plaintext");
        assert_eq!(std::fs::read(encrypted).unwrap(), b"existing ciphertext");
    }
}

#[test]
fn legacy_blank_password_encrypted_files_remain_readable() {
    // Construct the legacy v1 format directly: new encryption must reject
    // these passwords, but reading old files must still use the exact bytes.
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    for password in ["", "          "] {
        let salt = [7; SALT_LEN];
        let nonce = [9; NONCE_LEN];
        let key = derive_key(password.as_bytes(), &salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), mnemonic.as_bytes())
            .unwrap();
        let mut legacy = vec![1];
        legacy.extend_from_slice(&salt);
        legacy.extend_from_slice(&nonce);
        legacy.extend_from_slice(&ciphertext);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnemonic.enc");
        std::fs::write(&path, legacy).unwrap();
        assert_eq!(
            read_mnemonic(&path, Some(password)).unwrap().as_str(),
            mnemonic
        );
    }
}

#[test]
fn truncated_file_rejected() {
    let result = decrypt_mnemonic(&[0x01; 10], "password");
    assert!(matches!(
        result.unwrap_err(),
        MnemonicCryptoError::InvalidFormat(_)
    ));
}

#[test]
fn wrong_version_rejected() {
    let mut data = vec![0xFF]; // wrong version
    data.extend_from_slice(&[0u8; SALT_LEN + NONCE_LEN + 32]);
    let result = decrypt_mnemonic(&data, "password");
    assert!(matches!(
        result.unwrap_err(),
        MnemonicCryptoError::InvalidFormat(_)
    ));
}

#[test]
fn different_encryptions_produce_different_output() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let enc1 = encrypt_mnemonic(mnemonic, "password").unwrap();
    let enc2 = encrypt_mnemonic(mnemonic, "password").unwrap();
    // Different salt/nonce means different output
    assert_ne!(enc1, enc2);
    // But both decrypt to the same mnemonic
    assert_eq!(decrypt_mnemonic(&enc1, "password").unwrap().as_str(), mnemonic);
    assert_eq!(decrypt_mnemonic(&enc2, "password").unwrap().as_str(), mnemonic);
}

#[test]
fn is_encrypted_path_check() {
    assert!(is_encrypted_path(std::path::Path::new("/tmp/mnemonic.enc")));
    assert!(!is_encrypted_path(std::path::Path::new(
        "/tmp/mnemonic.txt"
    )));
    assert!(!is_encrypted_path(std::path::Path::new("/tmp/mnemonic")));
}

#[test]
fn write_and_read_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic.txt");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let final_path = write_mnemonic(&path, mnemonic, None).unwrap();
    assert_eq!(final_path, path);

    let read = read_mnemonic(&final_path, None).unwrap();
    assert_eq!(read.as_str(), mnemonic);
}

#[test]
fn plaintext_write_preserves_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic.txt");

    // Synthetic input only. The legacy plaintext format is the input bytes
    // verbatim, with no trimming, header, or added newline.
    for mnemonic in ["test phrase", " \ttest  phrase\r\n", ""] {
        let final_path = write_mnemonic(&path, mnemonic, None).unwrap();
        assert_eq!(final_path, path);
        assert_eq!(std::fs::read(&final_path).unwrap(), mnemonic.as_bytes());
    }
}

#[test]
fn write_and_read_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic.txt");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "  secret with spaces  ";

    let final_path = write_mnemonic(&path, mnemonic, Some(password)).unwrap();
    assert_eq!(final_path.extension().unwrap(), "enc");

    let read = read_mnemonic(&final_path, Some(password)).unwrap();
    assert_eq!(read.as_str(), mnemonic);

    // Wrong password should fail
    let result = read_mnemonic(&final_path, Some("wrong"));
    assert!(result.is_err());
}

#[test]
fn pre_zeroize_v1_fixture_still_decrypts() {
    // Fixed bytes produced by the old dependencies, not encrypt_mnemonic.
    // Pins KDF parameters, password whitespace, header layout and GCM tag.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic.enc");
    std::fs::write(&path, include_bytes!("fixtures/mnemonic-v1.enc")).unwrap();
    assert_eq!(
        read_mnemonic(&path, Some("  legacy-fixture-password  ")).unwrap().as_str(),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
}

/// The salt and the nonce come straight from the operating system: a forked
/// process does not repeat the parent's next values (a per-thread userspace
/// generator would), and two encryptions differ in each field separately.
#[cfg(unix)]
#[test]
fn salt_and_nonce_are_fresh_os_draws() {
    let header = || {
        let out = encrypt_mnemonic("abandon ability able about above absent absorb abstract absurd abuse access accident", "a long enough password").unwrap();
        out[1..1 + SALT_LEN + NONCE_LEN].to_vec()
    };
    // Each field on its own: a fresh other field must not hide a repeated one.
    assert!(
        draws_differ_across_fork(|| header()[..SALT_LEN].to_vec()),
        "salt repeats across fork"
    );
    assert!(
        draws_differ_across_fork(|| header()[SALT_LEN..].to_vec()),
        "nonce repeats across fork"
    );
    let (a, b) = (header(), header());
    assert_ne!(a[..SALT_LEN], b[..SALT_LEN], "salt repeated");
    assert_ne!(a[SALT_LEN..], b[SALT_LEN..], "nonce repeated");
}

/// Draw once, fork, draw in both processes: true when the two draws differ
/// (a per-thread userspace generator copied by fork would repeat).
#[cfg(unix)]
fn draws_differ_across_fork(draw: impl Fn() -> Vec<u8>) -> bool {
    let _warm = draw();
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds has room for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    // SAFETY: the child only draws, writes to the pipe and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&draw)) {
            Ok(bytes) => {
                // SAFETY: valid buffer and descriptor.
                let n = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), bytes.len()) };
                if n as usize == bytes.len() { 0 } else { 2 }
            }
            Err(_) => 1,
        };
        // SAFETY: leave the child without running the parent's destructors.
        unsafe { libc::_exit(code) };
    }
    let ours = draw();
    let mut theirs = vec![0u8; ours.len()];
    // SAFETY: close our copy of the write end so a dead child yields EOF.
    unsafe { libc::close(fds[1]) };
    let mut poll = libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 };
    // SAFETY: one valid pollfd; 20 s bound.
    let ready = unsafe { libc::poll(&mut poll, 1, 20_000) };
    let n = if ready == 1 {
        // SAFETY: valid buffer of theirs.len() bytes.
        unsafe { libc::read(fds[0], theirs.as_mut_ptr().cast(), theirs.len()) }
    } else {
        // SAFETY: pid is our child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        -1
    };
    let mut status = 0;
    // SAFETY: reap our child; close the read end.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
        libc::close(fds[0]);
    }
    assert_eq!(n as usize, ours.len(), "the forked child did not report its draw");
    ours != theirs
}
