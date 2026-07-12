//! CLI argument parsing — `konsensus init` and `konsensus start`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// BitSov v2 — sovereign mesh network node.
#[derive(Parser)]
#[command(name = "konsensus", version, about = "Sovereign mesh network node")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new node: generate identity and create config file.
    Init {
        /// Directory to create the node data in.
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Skip interactive prompts and use defaults.
        #[arg(long)]
        non_interactive: bool,

        /// Set the sovereignty tier directly (cloud, light, full).
        /// Implies --non-interactive for tier selection.
        #[arg(long)]
        tier: Option<String>,

        /// Encrypt the mnemonic file with a password.
        /// If set without a value, prompts for the password interactively.
        #[arg(long)]
        encrypt: Option<Option<String>>,
    },

    /// Start the node using an existing configuration.
    Start {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Password to decrypt an encrypted mnemonic file (`.enc`).
        /// If the mnemonic file has `.enc` extension and no password is
        /// provided, the node will prompt interactively.
        #[arg(long)]
        password: Option<String>,

        /// Override admission mode for this run: `whitelist` (default) or `price-open`.
        /// Operator-selectable price-admission mode; this is NOT an open network.
        /// When omitted, the config-file value (default `whitelist`) is used.
        #[arg(long, value_parser = ["whitelist", "price-open"])]
        admission_mode: Option<String>,
    },

    /// Print the node ID derived from a mnemonic file.
    ///
    /// Useful for scripts that need to extract node IDs for peer configuration.
    /// Either `--mnemonic` or `--config` must be provided. When `--config` is
    /// given, the mnemonic path is read from the configuration file.
    NodeId {
        /// Path to the mnemonic file.
        #[arg(short, long, required_unless_present = "config")]
        mnemonic: Option<PathBuf>,

        /// Path to the config file (extracts mnemonic path automatically).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// BIP-39 passphrase (optional).
        #[arg(short, long, default_value = "")]
        passphrase: String,
    },

    /// Restore a node from an existing 24-word mnemonic.
    ///
    /// Re-derives the identity from the mnemonic, creates a new config, and
    /// writes the mnemonic file. Use this to recover a node on a new device.
    Restore {
        /// Directory to create the node data in.
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// The 24-word mnemonic phrase (space-separated, quoted).
        /// If omitted, prompts interactively.
        #[arg(short, long)]
        mnemonic: Option<String>,

        /// Set the sovereignty tier directly (cloud, light, full).
        #[arg(long)]
        tier: Option<String>,

        /// Encrypt the mnemonic file with a password.
        #[arg(long)]
        encrypt: Option<Option<String>>,
    },

    /// Sign the auth challenge and print the hex signature.
    ///
    /// Used by smoke tests and scripts to authenticate against the node API.
    /// Outputs the hex-encoded Ed25519 signature of "konsensus-auth".
    /// Either `--mnemonic` or `--config` must be provided.
    SignChallenge {
        /// Path to the mnemonic file.
        #[arg(short, long, required_unless_present = "config")]
        mnemonic: Option<PathBuf>,

        /// Path to the config file (extracts mnemonic path automatically).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// BIP-39 passphrase (optional).
        #[arg(short, long, default_value = "")]
        passphrase: String,
    },

    /// Static channel backup (SCB) operations.
    Scb {
        #[command(subcommand)]
        command: ScbCommand,
    },

    /// Whitelist (peers + accepted invites) backup/restore for fresh-hardware recovery.
    Whitelist {
        #[command(subcommand)]
        command: WhitelistCommand,
    },
}

#[derive(Subcommand)]
pub enum ScbCommand {
    /// Restore an encrypted SCB backup and force-close restored channels.
    Restore {
        /// Path to the encrypted backup file (`*.aes`).
        #[arg(long)]
        from: PathBuf,

        /// Path to node config (for mnemonic + LDK settings).
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Directory where restored LDK state is imported.
        ///
        /// Defaults to `<node-data>/ldk-restore`. Refusing the live `ldk`
        /// directory by default keeps preview mode from mutating a running
        /// node's production store.
        #[arg(long)]
        restore_dir: Option<PathBuf>,

        /// Password to decrypt an encrypted mnemonic file (`.enc`), if needed.
        #[arg(long)]
        password: Option<String>,

        /// Required to execute destructive force-close operations.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub enum WhitelistCommand {
    /// Export the gate-whitelist state into an encrypted sidecar (RV-RESTORE).
    ///
    /// The SCB backs up only LDK channel state; this backs up the storage-DB
    /// whitelist (peers + accepted invites) so a fresh-hardware restore can
    /// re-admit invite-onboarded peers. Run on the SCB-rotation cadence and
    /// keep the file alongside `scb-latest.aes`.
    Backup {
        /// Path to node config (for mnemonic + storage settings).
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Output path. Defaults to `<backup.scb_dir>/whitelist-latest.aes`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Password to decrypt an encrypted mnemonic file (`.enc`), if needed.
        #[arg(long)]
        password: Option<String>,
    },

    /// Restore the gate-whitelist state from an encrypted sidecar into the
    /// configured storage DB (RV-RESTORE). Run after `scb restore` on fresh
    /// hardware so the node re-admits invite-onboarded peers. Idempotent.
    Restore {
        /// Path to the encrypted whitelist backup (`whitelist-latest.aes`).
        #[arg(long)]
        from: PathBuf,

        /// Path to node config (for mnemonic + storage settings).
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Password to decrypt an encrypted mnemonic file (`.enc`), if needed.
        #[arg(long)]
        password: Option<String>,
    },
}

#[cfg(test)]
#[path = "tests/cli.rs"]
mod tests;
