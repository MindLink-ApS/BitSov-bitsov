use super::*;
use clap::Parser;

#[test]
fn parse_init_defaults() {
    let cli = Cli::parse_from(["konsensus", "init"]);
    match cli.command {
        Command::Init {
            dir,
            non_interactive,
            tier,
            encrypt,
        } => {
            assert_eq!(dir, PathBuf::from("."));
            assert!(!non_interactive);
            assert!(tier.is_none());
            assert!(encrypt.is_none());
        }
        _ => panic!("expected Init command"),
    }
}

#[test]
fn parse_init_all_flags() {
    let cli = Cli::parse_from([
        "konsensus",
        "init",
        "--dir",
        "/data/node",
        "--non-interactive",
        "--tier",
        "full",
        "--encrypt",
        "my-password",
    ]);
    match cli.command {
        Command::Init {
            dir,
            non_interactive,
            tier,
            encrypt,
        } => {
            assert_eq!(dir, PathBuf::from("/data/node"));
            assert!(non_interactive);
            assert_eq!(tier.as_deref(), Some("full"));
            assert_eq!(encrypt, Some(Some("my-password".to_string())));
        }
        _ => panic!("expected Init command"),
    }
}

#[test]
fn parse_start_default_config() {
    let cli = Cli::parse_from(["konsensus", "start"]);
    match cli.command {
        Command::Start { config, password, admission_mode } => {
            assert_eq!(config, PathBuf::from("konsensus.toml"));
            assert!(password.is_none());
            // M1a: off-by-default — absence of the flag leaves the override None,
            // so cmd_start falls back to the config-file value (default Whitelist).
            assert!(admission_mode.is_none());
        }
        _ => panic!("expected Start command"),
    }
}

#[test]
fn parse_start_custom_config() {
    let cli = Cli::parse_from(["konsensus", "start", "--config", "/etc/konsensus.toml"]);
    match cli.command {
        Command::Start { config, password, admission_mode } => {
            assert_eq!(config, PathBuf::from("/etc/konsensus.toml"));
            assert!(password.is_none());
            assert!(admission_mode.is_none());
        }
        _ => panic!("expected Start command"),
    }
}

#[test]
fn parse_start_with_password() {
    let cli = Cli::parse_from(["konsensus", "start", "--password", "secret123"]);
    match cli.command {
        Command::Start { config, password, admission_mode } => {
            assert_eq!(config, PathBuf::from("konsensus.toml"));
            assert_eq!(password.as_deref(), Some("secret123"));
            assert!(admission_mode.is_none());
        }
        _ => panic!("expected Start command"),
    }
}

#[test]
fn parse_start_admission_mode_price_open() {
    // M1a CLI override: `--admission-mode price-open` is captured as Some("price-open").
    // cmd_start maps it to ReachabilityMode::PriceOpen before building the node.
    let cli = Cli::parse_from(["konsensus", "start", "--admission-mode", "price-open"]);
    match cli.command {
        Command::Start { config, password, admission_mode } => {
            assert_eq!(config, PathBuf::from("konsensus.toml"));
            assert!(password.is_none());
            assert_eq!(admission_mode.as_deref(), Some("price-open"));
        }
        _ => panic!("expected Start command"),
    }
}

#[test]
fn parse_start_admission_mode_rejects_unknown() {
    // clap's value_parser constrains the flag to {whitelist, price-open};
    // any other value is a parse error (defensive — never silently misconfigured).
    let result = Cli::try_parse_from(["konsensus", "start", "--admission-mode", "open"]);
    assert!(result.is_err(), "unknown admission mode must be rejected by clap");
}

#[test]
fn parse_node_id() {
    let cli = Cli::parse_from(["konsensus", "node-id", "--mnemonic", "/keys/m.txt"]);
    match cli.command {
        Command::NodeId {
            mnemonic,
            config,
            passphrase,
        } => {
            assert_eq!(mnemonic, Some(PathBuf::from("/keys/m.txt")));
            assert!(config.is_none());
            assert_eq!(passphrase, "");
        }
        _ => panic!("expected NodeId command"),
    }
}

#[test]
fn parse_node_id_with_config() {
    let cli = Cli::parse_from(["konsensus", "node-id", "--config", "/data/konsensus.toml"]);
    match cli.command {
        Command::NodeId {
            mnemonic,
            config,
            passphrase,
        } => {
            assert!(mnemonic.is_none());
            assert_eq!(config, Some(PathBuf::from("/data/konsensus.toml")));
            assert_eq!(passphrase, "");
        }
        _ => panic!("expected NodeId command"),
    }
}

#[test]
fn parse_node_id_with_passphrase() {
    let cli = Cli::parse_from([
        "konsensus",
        "node-id",
        "--mnemonic",
        "/keys/m.txt",
        "--passphrase",
        "secret",
    ]);
    match cli.command {
        Command::NodeId {
            mnemonic,
            config,
            passphrase,
        } => {
            assert_eq!(mnemonic, Some(PathBuf::from("/keys/m.txt")));
            assert!(config.is_none());
            assert_eq!(passphrase, "secret");
        }
        _ => panic!("expected NodeId command"),
    }
}

#[test]
fn parse_restore_defaults() {
    let cli = Cli::parse_from(["konsensus", "restore"]);
    match cli.command {
        Command::Restore {
            dir,
            mnemonic,
            tier,
            encrypt,
        } => {
            assert_eq!(dir, PathBuf::from("."));
            assert!(mnemonic.is_none());
            assert!(tier.is_none());
            assert!(encrypt.is_none());
        }
        _ => panic!("expected Restore command"),
    }
}

#[test]
fn parse_restore_with_mnemonic() {
    let cli = Cli::parse_from([
        "konsensus",
        "restore",
        "--dir",
        "/data",
        "--mnemonic",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "--tier",
        "light",
    ]);
    match cli.command {
        Command::Restore {
            dir,
            mnemonic,
            tier,
            ..
        } => {
            assert_eq!(dir, PathBuf::from("/data"));
            assert!(mnemonic.is_some());
            assert_eq!(tier.as_deref(), Some("light"));
        }
        _ => panic!("expected Restore command"),
    }
}

#[test]
fn parse_sign_challenge() {
    let cli = Cli::parse_from(["konsensus", "sign-challenge", "--mnemonic", "/keys/m.txt"]);
    match cli.command {
        Command::SignChallenge {
            mnemonic,
            config,
            passphrase,
        } => {
            assert_eq!(mnemonic, Some(PathBuf::from("/keys/m.txt")));
            assert!(config.is_none());
            assert_eq!(passphrase, "");
        }
        _ => panic!("expected SignChallenge command"),
    }
}

#[test]
fn parse_sign_challenge_with_config() {
    let cli = Cli::parse_from([
        "konsensus",
        "sign-challenge",
        "--config",
        "/data/konsensus.toml",
    ]);
    match cli.command {
        Command::SignChallenge {
            mnemonic,
            config,
            passphrase,
        } => {
            assert!(mnemonic.is_none());
            assert_eq!(config, Some(PathBuf::from("/data/konsensus.toml")));
            assert_eq!(passphrase, "");
        }
        _ => panic!("expected SignChallenge command"),
    }
}

#[test]
fn parse_sign_challenge_with_passphrase() {
    let cli = Cli::parse_from([
        "konsensus",
        "sign-challenge",
        "--mnemonic",
        "/keys/m.txt",
        "--passphrase",
        "my-pass",
    ]);
    match cli.command {
        Command::SignChallenge {
            mnemonic,
            config,
            passphrase,
        } => {
            assert_eq!(mnemonic, Some(PathBuf::from("/keys/m.txt")));
            assert!(config.is_none());
            assert_eq!(passphrase, "my-pass");
        }
        _ => panic!("expected SignChallenge command"),
    }
}

#[test]
fn parse_scb_restore() {
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
                crate::cli::ScbCommand::Restore {
                    from,
                    config,
                    restore_dir,
                    password,
                    confirm,
                },
        } => {
            assert_eq!(from, PathBuf::from("/tmp/scb-latest.aes"));
            assert_eq!(config, PathBuf::from("/tmp/konsensus.toml"));
            assert!(restore_dir.is_none());
            assert!(password.is_none());
            assert!(confirm);
        }
        _ => panic!("expected SCB restore command"),
    }
}

#[test]
fn parse_missing_subcommand_fails() {
    let result = Cli::try_parse_from(["konsensus"]);
    assert!(result.is_err());
}

#[test]
fn parse_unknown_subcommand_fails() {
    let result = Cli::try_parse_from(["konsensus", "unknown"]);
    assert!(result.is_err());
}

#[test]
fn parse_node_id_missing_both_fails() {
    // Either --mnemonic or --config is required for node-id
    let result = Cli::try_parse_from(["konsensus", "node-id"]);
    assert!(result.is_err());
}

#[test]
fn parse_sign_challenge_missing_both_fails() {
    // Either --mnemonic or --config is required for sign-challenge
    let result = Cli::try_parse_from(["konsensus", "sign-challenge"]);
    assert!(result.is_err());
}
