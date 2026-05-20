use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// A well-known BIP-39 test mnemonic (12 words for brevity in tests).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Helper: write a plaintext mnemonic file.
fn write_test_mnemonic(dir: &Path) -> Result<PathBuf> {
    let path = dir.join("mnemonic.txt");
    std::fs::write(&path, TEST_MNEMONIC)?;
    Ok(path)
}

// ── cmd_init tests ─────────────────────────────────────────────────

#[test]
fn init_light_tier_creates_config_and_mnemonic() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("light"), None)?;

    let config_path = dir.join("konsensus.toml");
    let mnemonic_path = dir.join("mnemonic.txt");
    assert!(config_path.exists(), "config file must exist");
    assert!(mnemonic_path.exists(), "mnemonic file must exist");

    // Config must parse cleanly
    let config = crate::config::NodeConfig::load(&config_path)?;
    assert_eq!(config.tier, crate::config::NodeTier::Light);

    // Mnemonic must be 24 words
    let mnemonic = std::fs::read_to_string(&mnemonic_path)?;
    assert_eq!(mnemonic.trim().split_whitespace().count(), 24);
    Ok(())
}

#[test]
fn init_full_tier_creates_config() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("full"), None)?;

    let config = crate::config::NodeConfig::load(&dir.join("konsensus.toml"))?;
    assert_eq!(config.tier, crate::config::NodeTier::Full);
    Ok(())
}

#[test]
fn init_cloud_tier_creates_config() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("cloud"), None)?;

    let config = crate::config::NodeConfig::load(&dir.join("konsensus.toml"))?;
    assert_eq!(config.tier, crate::config::NodeTier::Cloud);
    Ok(())
}

#[test]
fn init_rejects_already_initialized() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("light"), None)?;

    // Second init must fail
    let err = cmd_init(&dir, true, Some("light"), None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("already initialized"),
        "expected 'already initialized' error, got: {msg}"
    );
    Ok(())
}

#[test]
fn init_rejects_unknown_tier() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    let err = cmd_init(&dir, true, Some("enterprise"), None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown tier"),
        "expected 'unknown tier' error, got: {msg}"
    );
    Ok(())
}

#[test]
fn init_non_interactive_defaults_to_light() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    // non_interactive=true, tier_arg=None → defaults to Light
    cmd_init(&dir, true, None, None)?;

    let config = crate::config::NodeConfig::load(&dir.join("konsensus.toml"))?;
    assert_eq!(config.tier, crate::config::NodeTier::Light);
    Ok(())
}

#[test]
fn init_with_encryption_creates_enc_file() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("light"), Some(Some("test-pw".to_string())))?;

    let enc_path = dir.join("mnemonic.enc");
    let plain_path = dir.join("mnemonic.txt");
    assert!(enc_path.exists(), "encrypted mnemonic file must exist");
    assert!(!plain_path.exists(), "plaintext mnemonic should not exist when encrypted");

    // Verify it's actually encrypted (not valid UTF-8 plaintext)
    let raw = std::fs::read(&enc_path)?;
    assert!(raw[0] == 0x01, "first byte must be format version 0x01");

    // Round-trip: decrypt and verify it's a valid mnemonic
    let decrypted = mnemonic_crypto::read_mnemonic(&enc_path, Some("test-pw"))?;
    assert_eq!(decrypted.split_whitespace().count(), 24);
    Ok(())
}

// ── cmd_restore tests ──────────────────────────────────────────────

#[test]
fn restore_creates_config_and_mnemonic() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_restore(&dir, Some(TEST_MNEMONIC), Some("light"), None)?;

    let config_path = dir.join("konsensus.toml");
    let mnemonic_path = dir.join("mnemonic.txt");
    assert!(config_path.exists());
    assert!(mnemonic_path.exists());

    let stored = std::fs::read_to_string(&mnemonic_path)?;
    assert_eq!(stored.trim(), TEST_MNEMONIC);
    Ok(())
}

#[test]
fn restore_rejects_already_initialized() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_restore(&dir, Some(TEST_MNEMONIC), Some("light"), None)?;

    let err = cmd_restore(&dir, Some(TEST_MNEMONIC), Some("light"), None).unwrap_err();
    assert!(format!("{err}").contains("already initialized"));
    Ok(())
}

#[test]
fn restore_rejects_invalid_mnemonic() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    let err = cmd_restore(&dir, Some("invalid mnemonic words that are not bip39"), Some("light"), None)
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid mnemonic") || msg.contains("could not derive"),
        "expected mnemonic error, got: {msg}"
    );
    Ok(())
}

#[test]
fn restore_with_encryption() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_restore(
        &dir,
        Some(TEST_MNEMONIC),
        Some("full"),
        Some(Some("secret".to_string())),
    )?;

    let enc_path = dir.join("mnemonic.enc");
    assert!(enc_path.exists(), "encrypted mnemonic file must exist");

    let decrypted = mnemonic_crypto::read_mnemonic(&enc_path, Some("secret"))?;
    assert_eq!(decrypted, TEST_MNEMONIC);
    Ok(())
}

// ── cmd_node_id tests ──────────────────────────────────────────────

#[test]
fn node_id_prints_hex() -> Result<()> {
    let tmp = TempDir::new()?;
    let mnemonic_path = write_test_mnemonic(tmp.path())?;

    // cmd_node_id prints to stdout — just verify it doesn't error
    cmd_node_id(&mnemonic_path, "")?;
    Ok(())
}

#[test]
fn node_id_is_deterministic() -> Result<()> {
    // Same mnemonic + passphrase must always produce the same node ID
    let identity1 = konsensus_core::NodeIdentity::from_mnemonic(TEST_MNEMONIC, "")?;
    let identity2 = konsensus_core::NodeIdentity::from_mnemonic(TEST_MNEMONIC, "")?;
    assert_eq!(identity1.node_id(), identity2.node_id());
    Ok(())
}

#[test]
fn node_id_passphrase_changes_identity() -> Result<()> {
    let id_no_pass = konsensus_core::NodeIdentity::from_mnemonic(TEST_MNEMONIC, "")?;
    let id_with_pass = konsensus_core::NodeIdentity::from_mnemonic(TEST_MNEMONIC, "secret")?;
    assert_ne!(
        id_no_pass.node_id(),
        id_with_pass.node_id(),
        "different passphrases must produce different identities"
    );
    Ok(())
}

#[test]
fn node_id_missing_file_errors() {
    let err = cmd_node_id(Path::new("/nonexistent/mnemonic.txt"), "").unwrap_err();
    assert!(
        format!("{err}").contains("failed to read mnemonic"),
        "expected file read error"
    );
}

// ── cmd_sign_challenge tests ───────────────────────────────────────

#[test]
fn sign_challenge_produces_valid_signature() -> Result<()> {
    let tmp = TempDir::new()?;
    let mnemonic_path = write_test_mnemonic(tmp.path())?;

    // Just verify it doesn't error (output goes to stdout)
    cmd_sign_challenge(&mnemonic_path, "")?;
    Ok(())
}

#[test]
fn sign_challenge_signature_verifies() -> Result<()> {
    let identity = konsensus_core::NodeIdentity::from_mnemonic(TEST_MNEMONIC, "")?;
    let signature = identity.sign(b"konsensus-auth");

    // Verify the signature with the public key
    use ed25519_dalek::Verifier;
    let verifying_key = identity.ed25519_verifying_key();
    assert!(
        verifying_key.verify(b"konsensus-auth", &signature).is_ok(),
        "signature must verify with the identity's public key"
    );
    Ok(())
}

#[test]
fn sign_challenge_missing_file_errors() {
    let err = cmd_sign_challenge(Path::new("/nonexistent/mnemonic.txt"), "").unwrap_err();
    assert!(
        format!("{err}").contains("failed to read mnemonic"),
        "expected file read error"
    );
}

// ── init + node-id consistency ─────────────────────────────────────

#[test]
fn init_then_node_id_matches() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("light"), None)?;

    // Read the generated mnemonic
    let mnemonic = std::fs::read_to_string(dir.join("mnemonic.txt"))?;
    let identity = konsensus_core::NodeIdentity::from_mnemonic(mnemonic.trim(), "")?;

    // Verify the config's mnemonic_file points to the right identity
    let config = crate::config::NodeConfig::load(&dir.join("konsensus.toml"))?;
    let stored_mnemonic = mnemonic_crypto::read_mnemonic(&config.identity.mnemonic_file, None)?;
    let stored_identity = konsensus_core::NodeIdentity::from_mnemonic(&stored_mnemonic, "")?;

    assert_eq!(
        identity.node_id(),
        stored_identity.node_id(),
        "node ID from mnemonic file must match"
    );
    Ok(())
}

#[test]
fn restore_produces_same_identity_as_original() -> Result<()> {
    // Init a node
    let tmp1 = TempDir::new()?;
    let dir1 = tmp1.path().join("node");
    cmd_init(&dir1, true, Some("light"), None)?;

    // Read the generated mnemonic
    let mnemonic = std::fs::read_to_string(dir1.join("mnemonic.txt"))?;
    let original_id = konsensus_core::NodeIdentity::from_mnemonic(mnemonic.trim(), "")?;

    // Restore in a new directory using the same mnemonic
    let tmp2 = TempDir::new()?;
    let dir2 = tmp2.path().join("node");
    cmd_restore(&dir2, Some(mnemonic.trim()), Some("light"), None)?;

    let restored_mnemonic = std::fs::read_to_string(dir2.join("mnemonic.txt"))?;
    let restored_id = konsensus_core::NodeIdentity::from_mnemonic(restored_mnemonic.trim(), "")?;

    assert_eq!(
        original_id.node_id(),
        restored_id.node_id(),
        "restored identity must match original"
    );
    Ok(())
}

// ── StorageSessionAdapter tests ────────────────────────────────────

#[tokio::test]
async fn session_adapter_save_load_roundtrip() -> Result<()> {
    let storage = Arc::new(
        konsensus_storage::SqliteStorage::in_memory().await?,
    );
    let adapter = StorageSessionAdapter {
        storage: storage as Arc<dyn konsensus_storage::Storage>,
    };

    let peer_id = NodeId::from_hex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    let state = b"test-session-state-bytes";

    // Save
    konsensus_crypto::SessionStore::save_session(&adapter, &peer_id, state)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // Load
    let loaded = konsensus_crypto::SessionStore::load_session(&adapter, &peer_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    assert_eq!(loaded.as_deref(), Some(state.as_slice()));
    Ok(())
}

#[tokio::test]
async fn session_adapter_delete() -> Result<()> {
    let storage = Arc::new(
        konsensus_storage::SqliteStorage::in_memory().await?,
    );
    let adapter = StorageSessionAdapter {
        storage: storage as Arc<dyn konsensus_storage::Storage>,
    };

    let peer_id = NodeId::from_hex(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )?;

    // Save then delete
    konsensus_crypto::SessionStore::save_session(&adapter, &peer_id, b"data")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    konsensus_crypto::SessionStore::delete_session(&adapter, &peer_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // Should be gone
    let loaded = konsensus_crypto::SessionStore::load_session(&adapter, &peer_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    assert!(loaded.is_none(), "deleted session must not be found");
    Ok(())
}

#[tokio::test]
async fn session_adapter_list() -> Result<()> {
    let storage = Arc::new(
        konsensus_storage::SqliteStorage::in_memory().await?,
    );
    let adapter = StorageSessionAdapter {
        storage: storage as Arc<dyn konsensus_storage::Storage>,
    };

    let peer1 = NodeId::from_hex(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )?;
    let peer2 = NodeId::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;

    konsensus_crypto::SessionStore::save_session(&adapter, &peer1, b"s1")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    konsensus_crypto::SessionStore::save_session(&adapter, &peer2, b"s2")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let sessions = konsensus_crypto::SessionStore::list_sessions(&adapter)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    assert_eq!(sessions.len(), 2);
    assert!(sessions.contains(&peer1));
    assert!(sessions.contains(&peer2));
    Ok(())
}

#[tokio::test]
async fn session_adapter_load_nonexistent_returns_none() -> Result<()> {
    let storage = Arc::new(
        konsensus_storage::SqliteStorage::in_memory().await?,
    );
    let adapter = StorageSessionAdapter {
        storage: storage as Arc<dyn konsensus_storage::Storage>,
    };

    let peer_id = NodeId::from_hex(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )?;

    let loaded = konsensus_crypto::SessionStore::load_session(&adapter, &peer_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    assert!(loaded.is_none());
    Ok(())
}

#[tokio::test]
async fn session_adapter_overwrite() -> Result<()> {
    let storage = Arc::new(
        konsensus_storage::SqliteStorage::in_memory().await?,
    );
    let adapter = StorageSessionAdapter {
        storage: storage as Arc<dyn konsensus_storage::Storage>,
    };

    let peer_id = NodeId::from_hex(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    )?;

    // Save initial state
    konsensus_crypto::SessionStore::save_session(&adapter, &peer_id, b"version1")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // Overwrite with new state
    konsensus_crypto::SessionStore::save_session(&adapter, &peer_id, b"version2")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let loaded = konsensus_crypto::SessionStore::load_session(&adapter, &peer_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    assert_eq!(
        loaded.as_deref(),
        Some(b"version2".as_slice()),
        "overwritten session must return latest data"
    );
    Ok(())
}

// ── Mnemonic encryption round-trip via cmd_init ────────────────────

#[test]
fn init_encrypted_then_read_with_wrong_password_fails() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().join("node");

    cmd_init(&dir, true, Some("light"), Some(Some("correct-pw".to_string())))?;

    let enc_path = dir.join("mnemonic.enc");
    let err = mnemonic_crypto::read_mnemonic(&enc_path, Some("wrong-pw"));
    assert!(err.is_err(), "wrong password must fail decryption");
    Ok(())
}
