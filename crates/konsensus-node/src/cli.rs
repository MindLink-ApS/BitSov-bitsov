//! CLI argument parsing — `konsensus init` and `konsensus start`.

use std::path::PathBuf;

use clap::builder::TypedValueParser;
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
    /// Print a one-use enrollment ticket (and optionally a terminal QR).
    PairTicket {
        /// Emit the strict v1 schema using only the first endpoint for older apps.
        #[arg(long)]
        legacy: bool,
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
        #[arg(long)]
        qr: bool,
        /// Ticket lifetime: positive seconds, minutes, hours or days (s/m/h/d).
        #[arg(long, default_value = "24h", value_parser = crate::ticket_cmd::parse_ttl)]
        ttl: std::time::Duration,
    },
    /// Close channels and send funds to an owner-specified home address (local console only).
    MoveHome(crate::move_home_cmd::MoveHomeArgs),
    /// Rebind the latest cleanly stopped live store after a hardware move (owner console only).
    RebindInstance {
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },
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

        /// Encrypt using a password read once to EOF from an inherited descriptor
        /// (0 = stdin). UTF-8, at most 4096 bytes; trailing CR/LF is removed.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(i32).range(0..), conflicts_with = "encrypt")]
        password_fd: Option<i32>,
    },

    /// Start the node using an existing configuration.
    #[command(group(clap::ArgGroup::new("owner_password").multiple(true)))]
    Start {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Password to decrypt an encrypted mnemonic file (`.enc`).
        /// If the mnemonic file has `.enc` extension and no password is
        /// provided, the node will prompt interactively.
        #[arg(long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Read that password from a file instead of prompting. Opt-in: only a
        /// regular file readable by its owner alone (chmod 600) is accepted.
        /// Any program running as you can read it, including a paired app, so
        /// it protects the seed from other OS users only.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Read the password once to EOF from an inherited descriptor (0 = stdin).
        /// UTF-8, at most 4096 bytes; trailing CR/LF is removed. Touch ID requires
        /// --local-owner-device too. Nonzero descriptors require Unix.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(i32).range(0..), conflicts_with_all = ["password", "password_file"], group = "owner_password")]
        password_fd: Option<i32>,

        /// Home box: remote setup/unlock and local owner-device spend envelopes.
        /// Setup exits 75 for a service-manager restart; unlock continues in-process.
        /// Equivalent to --remote-unlock --local-owner-device; never opens a console.
        #[arg(long, group = "owner_password", conflicts_with_all = ["password", "password_file", "password_fd", "owner_control"])]
        home: bool,

        /// Wait for an existing owner device to unlock the encrypted seed over Noise.
        #[arg(long, group = "owner_password", conflicts_with_all = ["password", "password_file", "password_fd", "owner_control"])]
        remote_unlock: bool,

        /// Enable existing owner-approved devices to sign recipient-bound spend envelopes.
        /// Requires a descriptor password or remote unlock and an encrypted seed; does not open a console.
        #[arg(long, requires = "owner_password", conflicts_with_all = ["password", "password_file", "owner_control"])]
        local_owner_device: bool,

        /// Override admission mode for this run: `whitelist` (default) or `price-open`.
        /// Operator-selectable price-admission mode; this is NOT an open network.
        /// When omitted, the config-file value (default `whitelist`) is used.
        #[arg(long, value_parser = ["whitelist", "price-open"])]
        admission_mode: Option<String>,

        /// Run in OWNER mode: create `<data-dir>/control.sock` (mode 0600), the
        /// channel for console spend grants and live identity replacement (#76).
        ///
        /// Off by default, and deliberately explicit. A packaged sidecar app
        /// launches the node without this flag and is therefore a
        /// `read` + `receive` client that may request elevation and can never
        /// obtain it — the app owns the node's stdout and data directory, so no
        /// node-emitted secret could exclude it anyway. To spend from a client,
        /// run the node yourself with this flag and grant deliberately. Existing
        /// owner devices can instead use --local-owner-device's limited envelopes.
        #[arg(long)]
        owner_control: bool,
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

    /// Sign an auth challenge and print the hex Ed25519 signature.
    ///
    /// Used by smoke tests and `docs/ops/owner-token.sh` to mint an owner JWT
    /// via `POST /api/v1/auth/token`. The challenge must be the opaque string
    /// returned by `GET /api/v1/auth/challenge` (`bitsov-auth-v1:<nonce>:<exp>`).
    /// The signature is over the challenge bytes exactly as the token endpoint
    /// verifies them. The mnemonic is read from disk and never printed.
    /// Either `--mnemonic` or `--config` must be provided.
    SignChallenge {
        /// Opaque challenge from `GET /api/v1/auth/challenge`.
        #[arg(long)]
        challenge: String,

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

    /// Approve a first contact or sponsor gift on the owner's local node.
    Approve {
        #[command(subcommand)]
        command: ApprovalCommand,
    },

    /// The recovery phrase file: encrypt a plaintext one in place.
    Seed {
        #[command(subcommand)]
        command: SeedCommand,
    },

    /// Paired device keys: approve one once, list, or revoke.
    ///
    /// A device key lets the paired app open per-contact spend envelopes by
    /// signing them on the device (Touch ID), instead of `konsensus grant`.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
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

    /// Show paired clients and anything awaiting the owner's decision (#76).
    ///
    /// Talks to `<data-dir>/control.sock`, which exists only when the node was
    /// started with `--owner-control`.
    PairStatus {
        /// Path to the configuration file (its directory is the data directory).
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Grant a budget-scoped spend window a client requested (#76, G1).
    ///
    /// The owner channel. The requesting app can create the pending request and
    /// read its status over HTTP; only this command can write the grant. One
    /// command per budget window: `konsensus grant --op <id> --budget 2000
    /// --for 24h`. It prints the terms, then asks for the short approval code
    /// the node printed on its own terminal; typing it is the approval. A
    /// request for
    /// `front_door` (publish the front-door card only) takes no budget:
    /// `konsensus grant --op <id> [--for 1h]`.
    Grant {
        /// Also authorize capped LSP deductions from this same budget.
        #[arg(long)]
        allow_liquidity_fees: bool,
        /// Pending operation id from the app's elevation request.
        #[arg(long = "op")]
        op_id: String,

        /// Total budget in sats. Defaults to the app's proposal, if it made one.
        #[arg(long)]
        budget: Option<u64>,

        /// Window, e.g. `24h`, `90m`, `1h30m`. At most 24 h (the default).
        #[arg(long = "for")]
        for_: Option<String>,

        /// Most one call may spend, in sats. Defaults to the whole budget.
        #[arg(long)]
        per_call: Option<u64>,

        /// Per-recipient budget as `<node-id-or-ln-pubkey>=<sats>`. Repeatable.
        #[arg(long)]
        recipient: Vec<String>,

        /// Accepted for older scripts; has no effect. There is no separate
        /// yes/no question: typing the console code is the confirmation.
        #[arg(long, hide = true)]
        yes: bool,

        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Approve and execute replacement of this node's LIVE identity (#76).
    ///
    /// Destructive: it replaces the identity of a node that may hold funds and
    /// relationships. The recovery phrase is supplied here, by you, and is
    /// checked against the destination identity the requesting client was
    /// bound to. The node must be restarted afterwards — this command never
    /// starts or stops one.
    ApproveReplacement {
        /// Pending operation id from the client's replacement request.
        #[arg(long = "op")]
        op_id: String,

        /// The 24-word recovery phrase of the destination identity.
        /// Prompted for if omitted, so it need not appear in shell history.
        #[arg(long)]
        mnemonic: Option<String>,

        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Revoke spend grants now, without touching the pairing (G1).
    ///
    /// The client keeps read+receive; spend stops on its next request.
    GrantRevoke {
        /// Client whose grant to revoke.
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        client_id: Option<String>,

        /// Revoke every client's grant.
        #[arg(long)]
        all: bool,

        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Revoke a pairing, or bump its epoch to kill its outstanding tokens (#76).
    ///
    /// Reachable from the CLI as well as from an `admin`-holding client,
    /// because the client being revoked may be the compromised one.
    PairRevoke {
        /// Client to revoke.
        #[arg(long)]
        client_id: String,

        /// Keep the pairing and bump its epoch instead of deleting it.
        #[arg(long)]
        keep_pairing: bool,

        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Open a pairing window so another client can pair (#76).
    ///
    /// Without a window, pairing is accepted only while no client is paired.
    PairWindow {
        /// Window length in seconds.
        #[arg(long, default_value_t = 300)]
        seconds: u64,

        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },

    /// Repair a data directory the node refused to start from (#76).
    Repair {
        #[command(subcommand)]
        command: RepairCommand,
    },
}

/// Repair actions a refusal can name.
#[derive(Subcommand)]
pub enum RepairCommand {
    /// Finish an interrupted first-run transition by writing the marker.
    ///
    /// Named by the refusal a node emits when identity material exists but
    /// `NODE_INITIALIZED` does not — a crash between the rename and the marker.
    /// It writes the marker and nothing else. The node will not do this on its
    /// own, because doing it silently would make a crashed transition
    /// indistinguishable from a completed one.
    MarkInitialized {
        /// Path to the node config (same `-c` as `konsensus start`).
        ///
        /// The data directory is the config file's parent. When the file exists,
        /// its configured identity path is used so repair finds the same
        /// mnemonic startup would.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Required: this changes how the node classifies the directory.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub enum ScbCommand {
    /// Disabled: stale SCB state can lose funds. Use move-home on the current live node.
    Restore {
        /// Path to the encrypted backup file (`*.aes`).
        #[arg(long)]
        from: PathBuf,

        /// Path to node config (for mnemonic + LDK settings).
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,

        /// Legacy argument; restore is disabled before any import.
        #[arg(long)]
        restore_dir: Option<PathBuf>,

        /// Password to decrypt an encrypted mnemonic file (`.enc`), if needed.
        #[arg(long)]
        password: Option<String>,

        /// Legacy argument; cannot bypass the restore safety lock.
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
    /// configured storage DB (RV-RESTORE), independently of disabled SCB restore on fresh
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

/// Owner commands for the recovery-phrase file.
#[derive(Subcommand)]
pub enum SeedCommand {
    /// Encrypt a plaintext recovery phrase (mnemonic.txt) in place. Stop the
    /// node first. Asks for a new password twice, writes the `.enc`, checks it
    /// decrypts to the same node identity, points the config at it, and only
    /// then overwrites and removes the plaintext file.
    Encrypt {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },
}

/// Owner commands for paired device keys.
#[derive(Subcommand)]
pub enum DeviceCommand {
    /// Register a device key the app asked for. Prints the device and its
    /// fingerprint, then asks for the code the node printed.
    Approve {
        /// Pending registration id (the app shows the command).
        #[arg(long = "op")]
        op_id: String,
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },
    /// List registered and pending device keys.
    List {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },
    /// Retire a device key now; its spend envelopes end with it.
    Revoke {
        /// Key id (see `konsensus device list`).
        #[arg(long = "key")]
        key_id: String,
        /// Path to the configuration file.
        #[arg(short, long, default_value = "konsensus.toml")]
        config: PathBuf,
    },
}

/// Complete owner-reviewed tuples; no field is inferred from paired-app state.
#[derive(Subcommand)]
pub enum ApprovalCommand {
    /// Authorize one first contact within a live paired client's budget grant.
    FirstContact {
        /// Paired client id whose budget may pay this first contact.
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        client: String,
        /// Exact current budget grant operation id.
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        op: String,
        /// Recipient node key (64 hex characters).
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        to: String,
        /// Maximum admission plus first-message cost, in millisatoshis.
        #[arg(long)]
        max_msat: u64,
        /// Exact per-contact budget; must fit the grant and any existing cap.
        #[arg(long)]
        contact_budget_msat: Option<u64>,
        /// Config location selects the adjacent owner control socket.
        #[arg(short, long, default_value = "konsensus.toml", value_parser = ApprovalValueParser(clap::builder::PathBufValueParser::new().try_map(approval_config)))]
        config: PathBuf,
    },
    /// Pay the exact frozen sponsor candidate after comparing its six-digit code.
    Gift {
        /// Introduction id of the frozen sponsor candidate.
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        intro: String,
        /// Exact newcomer node key from that candidate.
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        newcomer: String,
        /// Exact invoice payment hash from that candidate.
        #[arg(long, value_parser = ApprovalValueParser(approval_string))]
        hash: String,
        /// Exact gift amount from the candidate, in millisatoshis.
        #[arg(long)]
        gift_msat: u64,
        /// Exact candidate fee ceiling, in millisatoshis.
        #[arg(long)]
        fee_max_msat: u64,
        /// Six ASCII digits compared with the newcomer; preserve leading zeros.
        #[arg(long, value_parser = ApprovalValueParser(approval_code))]
        code: String,
        /// Config location selects the adjacent owner control socket.
        #[arg(short, long, default_value = "konsensus.toml", value_parser = ApprovalValueParser(clap::builder::PathBufValueParser::new().try_map(approval_config)))]
        config: PathBuf,
    },
}

// Clap's function-parser adapter echoes the rejected input in its diagnostic.
// Escape that context too, so rejecting a control character cannot print it.
#[derive(Clone)]
struct ApprovalValueParser<P>(P);

impl<P: TypedValueParser> TypedValueParser for ApprovalValueParser<P> {
    type Value = P::Value;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        self.0.parse_ref(cmd, arg, value).map_err(|mut error| {
            error.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(format!("{value:?}")),
            );
            error
        })
    }
}

fn approval_string(value: &str) -> Result<String, String> {
    // Unicode formatting controls are not covered by char::is_control().
    if value.chars().any(|c| {
        c.is_control()
            || matches!(c,
                '\u{061c}' | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    }) || value.trim() != value
    {
        return Err(
            "approval values must not contain control characters, bidi or invisible formatting controls, or surrounding whitespace".into(),
        );
    }
    Ok(value.to_owned())
}

fn approval_config(value: PathBuf) -> Result<PathBuf, String> {
    approval_string(&value.as_os_str().to_string_lossy())?;
    Ok(value)
}

fn approval_code(value: &str) -> Result<String, String> {
    let value = approval_string(value)?;
    if value.len() == 6 && value.bytes().all(|b| b.is_ascii_digit()) {
        Ok(value)
    } else {
        Err("code must be exactly six ASCII digits".into())
    }
}

#[cfg(test)]
mod local_owner_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn home_flags_and_conflicts() {
        for flags in [
            vec!["--home"],
            vec!["--home", "--remote-unlock"],
            vec!["--home", "--local-owner-device"],
            vec!["--home", "--remote-unlock", "--local-owner-device"],
        ] {
            let cli = Cli::try_parse_from([vec!["konsensus", "start"], flags].concat())
                .expect("home mode accepts redundant legacy flags");
            let Command::Start { owner_control, .. } = cli.command else {
                panic!("expected start");
            };
            assert!(
                !owner_control,
                "home mode must never grant console authority"
            );
        }
        for conflicting in [
            vec!["--owner-control"],
            vec!["--password", "secret"],
            vec!["--password-file", "secret.txt"],
            vec!["--password-fd", "0"],
        ] {
            for flags in [
                [vec!["--home"], conflicting.clone()].concat(),
                [conflicting, vec!["--home"]].concat(),
            ] {
                let error = Cli::try_parse_from([vec!["konsensus", "start"], flags].concat())
                    .err()
                    .expect("home mode rejects console authority and password sources");
                assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
                assert!(error.to_string().contains("--home"));
            }
        }
    }

    #[test]
    fn remote_unlock_flags() {
        for args in [
            vec!["--remote-unlock"],
            vec!["--remote-unlock", "--local-owner-device"],
        ] {
            assert!(Cli::try_parse_from([vec!["konsensus", "start"], args].concat()).is_ok());
        }
        for args in [
            vec!["--password", "secret"],
            vec!["--password-file", "secret"],
            vec!["--password-fd", "0"],
            vec!["--owner-control"],
        ] {
            assert!(Cli::try_parse_from(
                [vec!["konsensus", "start", "--remote-unlock"], args].concat()
            )
            .is_err());
        }
    }

    #[test]
    fn local_owner_requires_descriptor_and_excludes_console_and_other_password_sources() {
        assert!(Cli::try_parse_from([
            "konsensus",
            "start",
            "--password-fd",
            "0",
            "--local-owner-device"
        ])
        .is_ok());
        for args in [
            vec!["--local-owner-device"],
            vec!["--local-owner-device", "--password", "secret"],
            vec!["--local-owner-device", "--password-file", "secret.txt"],
            vec![
                "--local-owner-device",
                "--password-fd",
                "0",
                "--owner-control",
            ],
            vec![
                "--local-owner-device",
                "--password-fd",
                "0",
                "--password",
                "secret",
            ],
            vec![
                "--local-owner-device",
                "--password-fd",
                "0",
                "--password-file",
                "secret.txt",
            ],
        ] {
            assert!(Cli::try_parse_from([vec!["konsensus", "start"], args].concat()).is_err());
        }
    }
}
