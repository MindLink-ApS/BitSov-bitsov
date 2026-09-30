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
         Restart the node from a terminal and type this password when it asks: that turns \
         Touch ID approvals on. (`--password-file` also starts it, but leaves Touch ID \
         approvals off.)",
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
    if !plaintext.is_absolute() {
        // A relative path resolves against whatever directory this runs in,
        // which may be another node's: never shred on a guess.
        anyhow::bail!(
            "mnemonic_file = {:?} in {} is relative; make it an absolute path first. Nothing was changed.",
            plaintext,
            config_path.display()
        );
    }
    if mnemonic_crypto::is_encrypted_path(&plaintext) {
        anyhow::bail!("the recovery phrase at {} is already encrypted; nothing to do", plaintext.display());
    }
    let meta = std::fs::symlink_metadata(&plaintext)
        .with_context(|| format!("cannot read {}", plaintext.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file (a symlink?); nothing was changed", plaintext.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            anyhow::bail!(
                "{} has {} hard links; overwriting it would also zero the other copies. Remove the \
                 extra links first (keep your written backup). Nothing was changed.",
                plaintext.display(),
                meta.nlink()
            );
        }
    }
    let encrypted = plaintext.with_extension("enc");
    // One run at a time: the lock is created exclusively and removed at the end.
    let _lock = Lock::take(&plaintext.with_extension("encrypting.lock"))?;
    if std::fs::symlink_metadata(&encrypted).is_ok() {
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

    // 1. Create the encrypted file exclusively (never overwrite, never follow
    //    a symlink), owner-only from the first byte, and make it durable.
    let bytes = mnemonic_crypto::encrypt_mnemonic(&mnemonic, password.as_str())
        .context("failed to encrypt the recovery phrase; nothing was changed")?;
    create_private(&encrypted, &bytes)
        .with_context(|| format!("failed to create {}; nothing was changed", encrypted.display()))?;
    let abandon = |why: String| -> anyhow::Error {
        let _ = std::fs::remove_file(&encrypted);
        anyhow::anyhow!("{why}; the encrypted file was removed and the plaintext file and config kept")
    };

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

    // 3. Point the config at it, and check it reloads that way. If anything
    //    fails here, undo only what can be proven undone.
    let repointed = crate::owner_cmd::align_config_mnemonic(config_path, &encrypted).and_then(|()| {
        let reloaded = NodeConfig::load_before_identity_validation(config_path)?;
        anyhow::ensure!(
            reloaded.identity.mnemonic_file == encrypted,
            "the updated config does not point at the encrypted file"
        );
        Ok(())
    });
    if let Err(e) = repointed {
        return Err(rollback_config(config_path, &plaintext, &encrypted, e));
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

/// After a failed repoint: put the config back on the plaintext and remove
/// the encrypted file only if the config is proven to point at the plaintext
/// again. Otherwise keep both files and say exactly where the config points.
fn rollback_config(config_path: &Path, plaintext: &Path, encrypted: &Path, cause: anyhow::Error) -> anyhow::Error {
    let restored = crate::owner_cmd::align_config_mnemonic(config_path, plaintext).is_ok()
        && NodeConfig::load_before_identity_validation(config_path)
            .is_ok_and(|c| c.identity.mnemonic_file == plaintext);
    if restored {
        let _ = std::fs::remove_file(encrypted);
        anyhow::anyhow!(
            "could not update {} ({cause}); the config was restored, the encrypted file removed and \
             the plaintext file kept. Nothing else changed.",
            config_path.display()
        )
    } else {
        anyhow::anyhow!(
            "could not update {} ({cause}), and could not confirm it points back at {}. BOTH files \
             were kept: {} (plaintext) and {} (encrypted, same words). Check mnemonic_file in the \
             config before starting the node.",
            config_path.display(),
            plaintext.display(),
            plaintext.display(),
            encrypted.display()
        )
    }
}

/// Create `path` exclusively with mode 0600, write, and flush file and dir.
fn create_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    sync_file_and_dir(path)
}

/// An exclusive lock file, removed on drop.
struct Lock(PathBuf);

impl Lock {
    fn take(path: &Path) -> Result<Self> {
        create_private(path, b"").map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "another `seed encrypt` is running (or one was interrupted): {} exists. If none \
                     is running, check that mnemonic_file in the config points at a file that \
                     exists, then remove the lock. Nothing was changed.",
                    path.display()
                )
            } else {
                anyhow::anyhow!("cannot create {}: {e}; nothing was changed", path.display())
            }
        })?;
        Ok(Self(path.to_path_buf()))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot read the password file {}", path.display()))?;
    if !before.is_file() {
        anyhow::bail!("{} is not a regular file (symlinks are refused)", path.display());
    }
    let mut file = std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    // Check the file actually opened, not just the name: a swap between the
    // check and the open is refused.
    let meta = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if (meta.dev(), meta.ino()) != (before.dev(), before.ino()) || !meta.is_file() {
            anyhow::bail!("{} changed while it was being opened; refusing it", path.display());
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} has mode {mode:o}; the password file must be readable by its owner only (chmod 600)",
                path.display()
            );
        }
        // SAFETY: getuid has no preconditions and cannot fail.
        let me = unsafe { libc::getuid() };
        if meta.uid() != me {
            anyhow::bail!("{} is owned by another user; refusing it", path.display());
        }
    }
    let mut raw = Zeroizing::new(String::new());
    std::io::Read::read_to_string(&mut file, &mut raw).with_context(|| format!("cannot read {}", path.display()))?;
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

    #[test]
    fn a_relative_mnemonic_path_is_refused_before_anything_changes() {
        let (dir, config, plaintext) = node();
        let mut c = NodeConfig::load_before_identity_validation(&config).unwrap();
        c.identity.mnemonic_file = PathBuf::from("mnemonic.txt");
        c.save(&config).unwrap();
        let before = std::fs::read(&config).unwrap();
        let err = encrypt_seed(&config, pw("correct horse battery")).unwrap_err();
        assert!(err.to_string().contains("is relative"), "{err}");
        assert!(plaintext.exists() && !dir.path().join("mnemonic.enc").exists());
        assert_eq!(std::fs::read(&config).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_linked_plaintext_is_refused_and_the_other_link_survives() {
        let (dir, config, plaintext) = node();
        let other = dir.path().join("backup-copy.txt");
        std::fs::hard_link(&plaintext, &other).unwrap();
        let err = encrypt_seed(&config, pw("correct horse battery")).unwrap_err();
        assert!(err.to_string().contains("hard links"), "{err}");
        assert_eq!(std::fs::read_to_string(&other).unwrap().trim(), PHRASE);
        assert!(!dir.path().join("mnemonic.enc").exists());
    }

    #[test]
    fn a_second_run_or_a_planted_enc_is_refused() {
        let (dir, config, plaintext) = node();
        // Another run holds the lock.
        std::fs::write(plaintext.with_extension("encrypting.lock"), b"").unwrap();
        let err = encrypt_seed(&config, pw("correct horse battery")).unwrap_err();
        assert!(err.to_string().contains("another `seed encrypt`"), "{err}");
        std::fs::remove_file(plaintext.with_extension("encrypting.lock")).unwrap();
        // A dangling symlink where the .enc would go is not followed.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("elsewhere"), dir.path().join("mnemonic.enc")).unwrap();
            let err = encrypt_seed(&config, pw("correct horse battery")).unwrap_err();
            assert!(err.to_string().contains("refusing to overwrite"), "{err}");
            assert!(!dir.path().join("elsewhere").exists());
        }
        assert!(plaintext.exists());
        // The lock does not outlive a run.
        assert!(!plaintext.with_extension("encrypting.lock").exists());
    }

    #[test]
    fn rollback_keeps_both_files_when_the_config_cannot_be_proven_restored() {
        let (dir, config, plaintext) = node();
        let encrypted = dir.path().join("mnemonic.enc");
        std::fs::write(&encrypted, b"enc").unwrap();
        crate::owner_cmd::align_config_mnemonic(&config, &encrypted).unwrap();
        // The config now names the .enc and can no longer be rewritten.
        let tmp = config.with_extension("toml.tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("block"), b"x").unwrap();
        let err = rollback_config(&config, &plaintext, &encrypted, anyhow::anyhow!("reload failed"));
        assert!(err.to_string().contains("BOTH files"), "{err}");
        assert!(encrypted.exists() && plaintext.exists(), "nothing the config may name is deleted");
    }

    #[test]
    fn seed_encrypt_then_a_typed_start_turns_touch_id_approvals_on() {
        use konsensus_api::pairing::device::SEED_NOT_ENCRYPTED;
        let (_dir, config, _) = node();
        let before = NodeConfig::load_before_identity_validation(&config).unwrap();
        assert_eq!(crate::owner_approval_key(&before, None, true, &node_id()).unwrap_err(), SEED_NOT_ENCRYPTED);
        encrypt_seed(&config, pw("correct horse battery")).unwrap();
        let after = NodeConfig::load_before_identity_validation(&config).unwrap();
        crate::owner_approval_key(&after, Some("correct horse battery"), true, &node_id())
            .expect("after seed encrypt and a typed start, device approvals are on");
    }
}
