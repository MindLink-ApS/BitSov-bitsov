use anyhow::Result;
use std::path::Path;

pub async fn cmd_scb_restore(
    _config_path: &Path,
    _mnemonic_password: Option<&str>,
    _from: &Path,
    _restore_dir: Option<&Path>,
    _confirm: bool,
) -> Result<()> {
    Err(konsensus_lightning::ScbRestoreError::Disabled.into())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::{Cli, Command, ScbCommand};

    #[tokio::test]
    async fn scb_restore_preview_and_confirm_fail_before_reading_config() {
        for confirm in [false, true] {
            let err = super::cmd_scb_restore(
                std::path::Path::new("/missing/config"),
                None,
                std::path::Path::new("/missing/backup"),
                None,
                confirm,
            )
            .await
            .unwrap_err();
            assert!(err.to_string().contains("disabled"), "{err}");
        }
    }

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
