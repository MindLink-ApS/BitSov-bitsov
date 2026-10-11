use super::*;

#[test]
fn encrypt_decrypt_roundtrip() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "test-password-123";

    let encrypted = encrypt_mnemonic(mnemonic, password).unwrap();
    assert!(encrypted.len() > HEADER_LEN);
    assert_eq!(encrypted[0], FORMAT_VERSION);

    let decrypted = decrypt_mnemonic(&encrypted, password).unwrap();
    assert_eq!(decrypted, mnemonic);
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
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
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
    assert_eq!(decrypt_mnemonic(&enc1, "password").unwrap(), mnemonic);
    assert_eq!(decrypt_mnemonic(&enc2, "password").unwrap(), mnemonic);
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
