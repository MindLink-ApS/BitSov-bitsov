//! `konsensus seed encrypt`: move a node from a plaintext recovery phrase to
//! an encrypted one, in place.
//!
//! Order is the safety property. Nothing is removed until the encrypted file
//! has been written, read back, and shown to derive the **same node
//! identity**, and until the config points at it and reloads. Any failure
//! before that leaves the plaintext file and the config exactly as they were.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::config::NodeConfig;
use crate::mnemonic_crypto;

/// Shortest password accepted for the recovery-phrase file.
pub const MIN_PASSWORD_CHARS: usize = 10;

/// What `seed encrypt` did.
#[derive(Debug)]
pub struct Encrypted {
    /// The new encrypted file.
    pub encrypted: PathBuf,
    /// The plaintext file that was overwritten and removed.
    pub removed: PathBuf,
    /// Node id both files derive.
    pub node_id: String,
}

/// `konsensus seed encrypt --config <path>`.
pub fn cmd_seed_encrypt(config_path: &Path) -> Result<()> {
    let config_path = crate::owner_cmd::absolute_config_path(config_path)?;
    refuse_if_node_running(&config_path)?;
    let done = encrypt_seed(&config_path, prompt_new_password)?;
    println!(
        "\nThe recovery phrase is now encrypted.\n  encrypted file:  {}\n  removed:         {} \
         (overwritten, then deleted)\n  node id:         {}\n\n\
         BACKUPS: your written 24 words are still your recovery, and they are all you need to \
         restore this node. The new password protects only this file. If you lose the password, \
         restore from the 24 words. On SSDs, APFS snapshots and Time Machine, older copies of the \
         plaintext file may still exist; they hold the same words as your backup.\n\n\
         Start the node as before; it asks for this password at start \
         (or see `konsensus start --password-file`).",
        done.encrypted.display(),
        done.removed.display(),
        done.node_id
    );
    Ok(())
}

/// A new password, typed twice on the terminal. Never from a flag,
/// environment variable or file.
fn prompt_new_password() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(
        rpassword::prompt_password(format!(
            "New password for the recovery-phrase file (at least {MIN_PASSWORD_CHARS} characters): "
        ))
        .context("failed to read the password from the terminal")?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Type it again: ")
            .context("failed to read the password from the terminal")?,
    );
    if *first != *second {
        anyhow::bail!("the passwords did not match; nothing was changed");
    }
    Ok(first)
}

/// Encrypting under a running node would leave it on a config it no longer
/// matches until restart; ask for it to be stopped first.
fn refuse_if_node_running(config_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let socket = crate::owner_cmd::data_dir_of(config_path).join(konsensus_api::control::SOCKET_FILE);
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            anyhow::bail!(
                "the node is running (its control socket answers at {}). Stop it first; nothing was changed.",
                socket.display()
            );
        }
    }
    let _ = config_path;
    Ok(())
}

/// The whole migration, with the password source injected (tests).
pub fn encrypt_seed(
    config_path: &Path,
    password: impl FnOnce() -> Result<Zeroizing<String>>,
) -> Result<Encrypted> {
    let config = NodeConfig::load_before_identity_validation(config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;
    let plaintext = config.identity.mnemonic_file.clone();
    if mnemonic_crypto::is_encrypted_path(&plaintext) {
        anyhow::bail!("the recovery phrase at {} is already encrypted; nothing to do", plaintext.display());
    }
    let encrypted = plaintext.with_extension("enc");
    if encrypted.try_exists()? {
        anyhow::bail!(
            "{} already exists; refusing to overwrite it. Nothing was changed.",
            encrypted.display()
        );
    }
    let mnemonic = mnemonic_crypto::read_mnemonic(&plaintext, None)
        .with_context(|| format!("failed to read the recovery phrase at {}", plaintext.display()))?;
    let passphrase = config.identity.passphrase.as_str();
    let node_id = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, passphrase)
        .context("the recovery phrase does not derive an identity; nothing was changed")?
        .node_id()
        .to_hex();

    let password = password()?;
    if password.chars().count() < MIN_PASSWORD_CHARS {
        anyhow::bail!("the password must be at least {MIN_PASSWORD_CHARS} characters; nothing was changed");
    }

    // 1. Write the encrypted file (0600) and make it durable.
    let written = mnemonic_crypto::write_mnemonic(&plaintext, &mnemonic, Some(password.as_str()))
        .context("failed to write the encrypted recovery phrase; nothing was changed")?;
    if written != encrypted {
        let _ = std::fs::remove_file(&written);
        anyhow::bail!("unexpected encrypted path {}; nothing was changed", written.display());
    }
    let abandon = |why: String| -> anyhow::Error {
        let _ = std::fs::remove_file(&encrypted);
        anyhow::anyhow!("{why}; the encrypted file was removed and the plaintext file kept")
    };
    sync_file_and_dir(&encrypted).map_err(|e| abandon(format!("could not flush {}: {e}", encrypted.display())))?;

    // 2. Read it back: same words, same identity.
    let back = mnemonic_crypto::read_mnemonic(&encrypted, Some(password.as_str()))
        .map_err(|e| abandon(format!("the encrypted file did not decrypt ({e})")))?;
    let back_id = konsensus_core::NodeIdentity::from_mnemonic(&back, passphrase)
        .map_err(|e| abandon(format!("the decrypted phrase does not derive an identity ({e})")))?
        .node_id()
        .to_hex();
    if *back != *mnemonic || back_id != node_id {
        return Err(abandon("the encrypted file does not derive the same identity".into()));
    }

    // 3. Point the config at it, and check it reloads that way.
    crate::owner_cmd::align_config_mnemonic(config_path, &encrypted)
        .map_err(|e| abandon(format!("could not update {} ({e})", config_path.display())))?;
    let reloaded = NodeConfig::load_before_identity_validation(config_path)
        .map_err(|e| abandon(format!("the updated config does not load ({e})")))?;
    if reloaded.identity.mnemonic_file != encrypted {
        // Put the config back before removing the encrypted file.
        let _ = crate::owner_cmd::align_config_mnemonic(config_path, &plaintext);
        return Err(abandon("the updated config does not point at the encrypted file".into()));
    }

    // 4. Only now remove the plaintext: overwrite, flush, delete, flush the dir.
    shred(&plaintext).with_context(|| {
        format!(
            "the node now uses {}, but removing the plaintext {} failed; delete it by hand",
            encrypted.display(),
            plaintext.display()
        )
    })?;
    Ok(Encrypted { encrypted, removed: plaintext, node_id })
}

fn sync_file_and_dir(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Overwrite a small file with zeros, flush, delete, flush the directory.
/// Best effort on copy-on-write filesystems (APFS) and SSDs, which the
/// command's message says.
fn shred(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file; not removing it"));
    }
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(&vec![0u8; meta.len() as usize])?;
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// `konsensus start --password-file <path>`: read the recovery-phrase password
/// from a file the owner opted into. Only a regular file (not a symlink) with
/// no group or other permissions (0600 or 0400) is accepted.
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot read the password file {}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file (symlinks are refused)", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} has mode {mode:o}; the password file must be readable by its owner only (chmod 600)",
                path.display()
            );
        }
    }
    let raw = Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    let pw = Zeroizing::new(raw.trim_end_matches(['\n', '\r']).to_string());
    if pw.is_empty() {
        anyhow::bail!("the password file {} is empty", path.display());
    }
    Ok(pw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeTier;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn node() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let phrase = mnemonic_crypto::write_mnemonic(&dir.path().join("mnemonic.txt"), PHRASE, None).unwrap();
        let config = dir.path().join("konsensus.toml");
        NodeConfig::default_for_tier(NodeTier::Light, phrase.clone(), dir.path()).save(&config).unwrap();
        (dir, config, phrase)
    }

    fn pw(p: &'static str) -> impl FnOnce() -> Result<Zeroizing<String>> {
        move || Ok(Zeroizing::new(p.to_string()))
    }

    fn node_id() -> String {
        konsensus_core::NodeIdentity::from_mnemonic(PHRASE, "").unwrap().node_id().to_hex()
    }

    #[test]
    fn encrypts_verifies_repoints_and_only_then_removes_the_plaintext() {
        let (dir, config, plaintext) = node();
        let done = encrypt_seed(&config, pw("correct horse battery")).unwrap();
        assert_eq!(done.node_id, node_id());
        assert!(!plaintext.exists(), "the plaintext phrase is gone");
        assert_eq!(done.encrypted, dir.path().join("mnemonic.enc"));
        // The config now points at it, and it decrypts to the same identity.
        let reloaded = NodeConfig::load_before_identity_validation(&config).unwrap();
        assert_eq!(reloaded.identity.mnemonic_file, done.encrypted);
        let back = mnemonic_crypto::read_mnemonic(&done.encrypted, Some("correct horse battery")).unwrap();
        assert_eq!(&*back, PHRASE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&done.encrypted).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // A second run has nothing to do and changes nothing.
        assert!(encrypt_seed(&config, pw("correct horse battery")).unwrap_err().to_string().contains("already encrypted"));
    }

    #[test]
    fn a_refusal_before_the_write_changes_nothing() {
        let (dir, config, plaintext) = node();
        let before = std::fs::read(&config).unwrap();
        // Too short.
        assert!(encrypt_seed(&config, pw("short")).is_err());
        // The password prompt failing (e.g. mismatch, no terminal).
        assert!(encrypt_seed(&config, || anyhow::bail!("the passwords did not match")).is_err());
        // An existing .enc is never overwritten.
        std::fs::write(dir.path().join("mnemonic.enc"), b"other").unwrap();
        assert!(encrypt_seed(&config, pw("correct horse battery")).unwrap_err().to_string().contains("refusing to overwrite"));
        assert_eq!(std::fs::read(dir.path().join("mnemonic.enc")).unwrap(), b"other");
        // Through all of it: plaintext intact, config untouched.
        assert_eq!(std::fs::read_to_string(&plaintext).unwrap().trim(), PHRASE);
        assert_eq!(std::fs::read(&config).unwrap(), before);
    }

    #[test]
    fn a_config_that_cannot_be_updated_keeps_the_plaintext_and_removes_the_new_file() {
        let (dir, config, plaintext) = node();
        // Make the config's directory entry unwritable by replacing the config
        // with a directory-backed path the atomic writer cannot rename over.
        let tmp = config.with_extension("toml.tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("block"), b"x").unwrap();
        let err = encrypt_seed(&config, pw("correct horse battery")).unwrap_err();
        assert!(err.to_string().contains("plaintext file kept"), "{err}");
        assert!(plaintext.exists(), "plaintext kept");
        assert!(!dir.path().join("mnemonic.enc").exists(), "new file removed");
        let reloaded = NodeConfig::load_before_identity_validation(&config).unwrap();
        assert_eq!(reloaded.identity.mnemonic_file, plaintext, "config unchanged");
    }

    #[test]
    fn the_password_file_must_be_private_and_regular() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw");
        std::fs::write(&file, "correct horse battery\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_password_file(&file).unwrap_err().to_string().contains("chmod 600"));
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(&*read_password_file(&file).unwrap(), "correct horse battery");
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_password_file(&link).unwrap_err().to_string().contains("symlinks"));
            let empty = dir.path().join("empty");
            std::fs::write(&empty, "\n").unwrap();
            std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_password_file(&empty).is_err());
        }
    }
}
