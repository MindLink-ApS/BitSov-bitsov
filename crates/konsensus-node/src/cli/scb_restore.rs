use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{LightningConfig, NodeConfig};

pub async fn cmd_scb_restore(
    config_path: &Path,
    mnemonic_password: Option<&str>,
    from: &Path,
    restore_dir: Option<&Path>,
    confirm: bool,
) -> Result<()> {
    let config = NodeConfig::load(config_path)
        .with_context(|| format!("failed to load config: {}", config_path.display()))?;

    let (network, esplora_url) = match &config.lightning {
        LightningConfig::Ldk {
            network,
            esplora_url,
            ..
        } => (network.clone(), esplora_url.clone()),
        other => anyhow::bail!(
            "scb restore requires [lightning] backend = \"ldk\" (found: {})",
            other.backend_name()
        ),
    };

    let mnemonic =
        crate::mnemonic_crypto::read_mnemonic(&config.identity.mnemonic_file, mnemonic_password)
            .with_context(|| {
                format!(
                    "failed to read mnemonic from {} (encrypted: {})",
                    config.identity.mnemonic_file.display(),
                    crate::mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file),
                )
            })?;

    let ldk_entropy_seed = konsensus_lightning::scb_restore::derive_ldk_entropy_seed(
        &mnemonic,
        Some(config.identity.passphrase.as_str()).filter(|s| !s.is_empty()),
    )?;
    let scb_key =
        konsensus_lightning::scb_restore::derive_scb_master_key_from_ldk_seed(&ldk_entropy_seed);

    let encrypted = fs::read(from)
        .with_context(|| format!("failed to read SCB backup file: {}", from.display()))?;

    let data_dir = config
        .identity
        .mnemonic_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let live_ldk_storage_dir = data_dir.join("ldk");
    let restore_storage_dir: PathBuf = restore_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join("ldk-restore"));

    if canonical_target(&restore_storage_dir)? == canonical_target(&live_ldk_storage_dir)? {
        anyhow::bail!(
            "refusing to restore into live LDK storage dir {}. Use a fresh --restore-dir",
            live_ldk_storage_dir.display()
        );
    }

    let restored = konsensus_lightning::decrypt_and_load_scb_backup(
        &encrypted,
        &scb_key,
        ldk_entropy_seed,
        &restore_storage_dir,
        &network,
        &esplora_url,
    )?;

    println!("SCB restore loaded from: {}", from.display());
    println!(
        "Imported recovery state into: {}",
        restore_storage_dir.display()
    );
    println!();
    println!("Recovered channel estimate:");

    if restored.estimates.is_empty() {
        println!("  (no claimable channel balances detected)");
    } else {
        for est in &restored.estimates {
            println!(
                "  channel_id={} counterparty={} estimated_recoverable_sats={}",
                est.channel_id, est.counterparty, est.amount_sats
            );
        }
    }

    // RV-RESTORE consumer: the SCB above carries only LDK channel-monitor state.
    // The gate whitelist (peers + accepted_invites in konsensus.db) lives in the
    // encrypted `whitelist-latest.aes` sidecar the node writes on the SCB cadence.
    // Apply it (if present) to the LIVE konsensus.db — independent of the --confirm
    // force-close gate below, because it is non-destructive relationship recovery —
    // so the restored node re-admits invite-onboarded peers at the gate on next
    // start. Look next to the SCB first, then the configured backup dir.
    println!();
    // Provenance guard (Codex #208): only AUTO-apply a whitelist sidecar from a
    // trusted location. A sidecar beside `--from` is trusted ONLY when `--from`
    // itself lives in the configured backup dir; a sidecar merely co-located with
    // an out-of-backup-dir `--from` (e.g. an unrelated `whitelist-latest.aes` in
    // /tmp) has unverified provenance and could re-admit an UNRELATED node's peers
    // into the gate whitelist, so it is never applied silently. The configured
    // backup dir is always trusted; anything else must be applied deliberately via
    // `konsensus whitelist restore`.
    let configured =
        Path::new(&config.backup.scb_dir).join(crate::whitelist_cmd::WHITELIST_BACKUP_NAME);
    let sidecar_beside = from
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(crate::whitelist_cmd::WHITELIST_BACKUP_NAME);
    let from_in_backup_dir = {
        let backup_dir_canon = canonical_target(Path::new(&config.backup.scb_dir)).ok();
        let from_dir_canon =
            canonical_target(from.parent().unwrap_or_else(|| Path::new("."))).ok();
        matches!((backup_dir_canon, from_dir_canon), (Some(b), Some(f)) if b == f)
    };
    let sidecar = if from_in_backup_dir && sidecar_beside.exists() {
        Some(sidecar_beside.clone())
    } else if configured.exists() {
        Some(configured.clone())
    } else {
        None
    };
    // A sidecar sitting beside an out-of-backup-dir `--from` is NOT auto-applied —
    // surface it so the operator can apply it deliberately after verifying it.
    if !from_in_backup_dir && sidecar_beside.exists() {
        println!(
            "NOTE: a whitelist sidecar ({}) sits next to --from but OUTSIDE the configured \
             backup dir {} — NOT auto-applying it (unverified provenance). If you trust it, \
             apply it explicitly: konsensus whitelist restore --from {}",
            crate::whitelist_cmd::WHITELIST_BACKUP_NAME,
            config.backup.scb_dir,
            sidecar_beside.display()
        );
    }
    match sidecar {
        Some(path) => {
            crate::whitelist_cmd::cmd_whitelist_restore(config_path, mnemonic_password, &path)
                .await
                .context("whitelist sidecar restore failed")?;
        }
        None => {
            println!(
                "No whitelist sidecar ({}) found next to the SCB or in {} — peer/invite \
                 whitelist will NOT be recovered. Run `konsensus whitelist backup` on the \
                 source node and `konsensus whitelist restore` here to recover relationships.",
                crate::whitelist_cmd::WHITELIST_BACKUP_NAME,
                config.backup.scb_dir
            );
        }
    }

    if !confirm {
        restored
            .node
            .stop()
            .map_err(|e| anyhow::anyhow!("failed to stop restored LDK node: {e}"))?;
        anyhow::bail!(
            "refusing to force-close without --confirm. Re-run with --confirm to broadcast unilateral closes"
        );
    }

    let forced = konsensus_lightning::force_close_restored_channels(&restored.node)?;
    if forced.is_empty() {
        println!("No open channels were found for force-close.");
    } else {
        println!();
        println!("Force-close initiated for {} channel(s):", forced.len());
        for channel_id in forced {
            println!("  user_channel_id={channel_id}");
        }
    }

    restored
        .node
        .stop()
        .map_err(|e| anyhow::anyhow!("failed to stop restored LDK node: {e}"))?;

    Ok(())
}

fn canonical_target(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .with_context(|| format!("failed to canonicalize {}", path.display()));
    }

    let mut cursor = path;
    let mut suffix = Vec::new();
    while !cursor.exists() {
        if let Some(name) = cursor.file_name() {
            suffix.push(name.to_owned());
        }
        cursor = cursor.parent().unwrap_or_else(|| Path::new("."));
        if cursor.as_os_str().is_empty() {
            cursor = Path::new(".");
            break;
        }
    }

    let mut out = fs::canonicalize(cursor)
        .with_context(|| format!("failed to canonicalize parent {}", cursor.display()))?;
    for name in suffix.iter().rev() {
        out.push(name);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::{Cli, Command, ScbCommand};

    #[test]
    fn scb_restore_cli() {
        let cli = Cli::parse_from([
            "konsensus",
            "scb",
            "restore",
            "--from",
            "/tmp/scb-latest.aes",
            "--config",
            "/tmp/konsensus.toml",
            "--confirm",
        ]);

        match cli.command {
            Command::Scb {
                command:
                    ScbCommand::Restore {
                        from,
                        config,
                        restore_dir,
                        password,
                        confirm,
                    },
            } => {
                assert_eq!(from, std::path::PathBuf::from("/tmp/scb-latest.aes"));
                assert_eq!(config, std::path::PathBuf::from("/tmp/konsensus.toml"));
                assert!(restore_dir.is_none());
                assert!(password.is_none());
                assert!(confirm);
            }
            _ => panic!("expected scb restore command"),
        }
    }
}
