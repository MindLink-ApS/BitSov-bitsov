//! `konsensus chain-tip`: show where the chain tip comes from, or explicitly
//! move an existing config to a tip the owner runs, or accept a public explorer.
//!
//! Nothing else changes a config's chain source: start only warns and labels.
//! Order is the safety property. The new source is checked first (reachable,
//! synchronized, and on the `[lightning]` network); the edited file is checked
//! to differ from the old one only where intended and to validate; the old file
//! is copied to a backup; then the config is replaced atomically. Any refusal
//! leaves the config byte for byte as it was.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::{BlockHash, Network};
use konsensus_core::traits::chain::ChainProvider;

use crate::chain_tip::{explorer_default, public_explorer_host};
use crate::config::{ChainConfig, LightningConfig, NodeConfig};

/// Bound on the whole new-source check. A slow source counts as unreachable.
const SOURCE_CHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// Networks a source can be identified as, by genesis block.
const KNOWN_NETWORKS: [Network; 5] = [
    Network::Bitcoin,
    Network::Testnet,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

#[derive(clap::Args, Debug, Default)]
pub struct ChainTipArgs {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "konsensus.toml")]
    pub config: PathBuf,

    /// Move to a tip you own: `bitcoind` (your Bitcoin Core, pruned is fine)
    /// or `electrum` (your Electrum server, itself backed by your Core).
    #[arg(long, value_parser = ["bitcoind", "electrum"], conflicts_with = "accept_third_party_tip")]
    pub chain: Option<String>,

    /// Bitcoin Core RPC host (default 127.0.0.1). A bare hostname or IP.
    #[arg(long)]
    pub rpc_host: Option<String>,

    /// Bitcoin Core RPC port (default: Core's port for the `[lightning]` network).
    #[arg(long)]
    pub rpc_port: Option<u16>,

    /// Absolute path to Core's cookie file (default: `$HOME/.bitcoin/<network dir>/.cookie`).
    #[arg(long, conflicts_with_all = ["rpc_user", "rpc_password_file"])]
    pub cookie_file: Option<PathBuf>,

    /// Core RPC user, with `--rpc-password-file` instead of a cookie.
    #[arg(long, requires = "rpc_password_file")]
    pub rpc_user: Option<String>,

    /// Absolute path to a file holding only the Core RPC password.
    #[arg(long, requires = "rpc_user")]
    pub rpc_password_file: Option<PathBuf>,

    /// Your Electrum server, `ssl://host:port` or `tcp://local-host:port`.
    #[arg(long)]
    pub electrum_server_url: Option<String>,

    /// Must be `own`: this command moves only to a server you run.
    #[arg(long, value_parser = ["own", "third_party"])]
    pub electrum_operator: Option<String>,

    /// Keep the configured Esplora explorer as a `third_party` tip, record that
    /// choice in `[chain]`, and silence the start-time warning.
    #[arg(long)]
    pub accept_third_party_tip: bool,
}

/// What the owner asked for, checked before the config is read.
enum Request {
    Show,
    Accept,
    Switch(SourceArgs),
}

enum SourceArgs {
    Bitcoind {
        host: String,
        port: Option<u16>,
        auth: Option<CoreAuth>,
    },
    Electrum {
        server_url: String,
    },
}

enum CoreAuth {
    Cookie(PathBuf),
    UserPassword(String, PathBuf),
}

fn refuse(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{message}; nothing was changed")
}

impl ChainTipArgs {
    fn request(&self) -> Result<Request> {
        let core_flags = self.rpc_host.is_some()
            || self.rpc_port.is_some()
            || self.cookie_file.is_some()
            || self.rpc_user.is_some()
            || self.rpc_password_file.is_some();
        let electrum_flags = self.electrum_server_url.is_some() || self.electrum_operator.is_some();
        let chain = self.chain.as_deref();
        if core_flags && chain != Some("bitcoind") {
            return Err(refuse("Bitcoin Core options require --chain bitcoind"));
        }
        if electrum_flags && chain != Some("electrum") {
            return Err(refuse("Electrum options require --chain electrum"));
        }
        if self.accept_third_party_tip {
            return Ok(Request::Accept);
        }
        let absolute = |path: &PathBuf, flag: &str| -> Result<PathBuf> {
            if path.is_absolute() {
                Ok(path.clone())
            } else {
                Err(refuse(format!("{flag} must be an absolute path")))
            }
        };
        match chain {
            None => Ok(Request::Show),
            Some("bitcoind") => {
                let auth = match (&self.cookie_file, &self.rpc_user, &self.rpc_password_file) {
                    (Some(cookie), None, None) => {
                        Some(CoreAuth::Cookie(absolute(cookie, "--cookie-file")?))
                    }
                    (None, Some(user), Some(file)) => Some(CoreAuth::UserPassword(
                        user.clone(),
                        absolute(file, "--rpc-password-file")?,
                    )),
                    _ => None,
                };
                Ok(Request::Switch(SourceArgs::Bitcoind {
                    host: self.rpc_host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    port: self.rpc_port,
                    auth,
                }))
            }
            Some("electrum") => {
                let server_url = self.electrum_server_url.clone().ok_or_else(|| {
                    refuse("--chain electrum requires --electrum-server-url; there is no default server")
                })?;
                match self.electrum_operator.as_deref() {
                    Some("own") => {}
                    Some(_) => {
                        return Err(refuse(
                            "this command moves only to an Electrum server you run (--electrum-operator own); \
                             to keep a third-party source, use --accept-third-party-tip",
                        ))
                    }
                    None => {
                        return Err(refuse(
                            "--chain electrum requires --electrum-operator own, declaring that you run the server",
                        ))
                    }
                }
                Ok(Request::Switch(SourceArgs::Electrum { server_url }))
            }
            Some(other) => Err(refuse(format!("unknown chain source {other}"))),
        }
    }
}

/// The Bitcoin network `[lightning]` pays on, when it states a known one.
pub(crate) fn configured_network(lightning: &LightningConfig) -> Option<Network> {
    let name = match lightning {
        LightningConfig::Ldk { network, .. } | LightningConfig::Cln { network, .. } => network,
        _ => return None,
    };
    match name.to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Some(Network::Bitcoin),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// Bitcoin Core's default RPC port and data subdirectory for `network`: the
/// same values a fresh Full init writes.
pub(crate) fn core_defaults(network: Network) -> (u16, &'static str) {
    match network {
        Network::Bitcoin => (8332, ""),
        Network::Testnet => (18332, "testnet3"),
        Network::Testnet4 => (48332, "testnet4"),
        Network::Signet => (38332, "signet"),
        Network::Regtest => (18443, "regtest"),
    }
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin (mainnet)",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn network_of_genesis(hash: BlockHash) -> Option<Network> {
    KNOWN_NETWORKS
        .into_iter()
        .find(|n| bitcoin::blockdata::constants::genesis_block(*n).block_hash() == hash)
}

/// The `[chain]` stanza for the requested owned source.
fn owned_chain(source: SourceArgs, network: Network, home: Option<PathBuf>) -> Result<ChainConfig> {
    match source {
        SourceArgs::Bitcoind { host, port, auth } => {
            let (default_port, subdir) = core_defaults(network);
            let (cookie_file, rpc_user, rpc_password_file) = match auth {
                Some(CoreAuth::Cookie(path)) => (Some(path), None, None),
                Some(CoreAuth::UserPassword(user, file)) => (None, Some(user), Some(file)),
                None => {
                    let home = home.filter(|h| h.is_absolute()).ok_or_else(|| {
                        refuse("HOME is not set to an absolute path; pass --cookie-file")
                    })?;
                    let mut cookie = home.join(".bitcoin");
                    if !subdir.is_empty() {
                        cookie.push(subdir);
                    }
                    (Some(cookie.join(".cookie")), None, None)
                }
            };
            let rpc = konsensus_chain::BitcoindConfig {
                rpc_host: host,
                rpc_port: port.unwrap_or(default_port),
                cookie_file,
                rpc_user,
                rpc_password_file,
            };
            rpc.validate().map_err(refuse)?;
            Ok(ChainConfig::Bitcoind(rpc))
        }
        SourceArgs::Electrum { server_url } => {
            let server = konsensus_chain::ElectrumConfig {
                server_url,
                operator: konsensus_chain::ElectrumOperator::Own,
            };
            server.validate().map_err(refuse)?;
            Ok(ChainConfig::Electrum(server))
        }
    }
}

/// Check the new source before anything is written: it answers, is on the
/// configured network (by genesis block), and reports itself synchronized.
/// Returns its height.
pub(crate) async fn check_source(chain: &ChainConfig, network: Network) -> Result<u64> {
    let provider: Box<dyn ChainProvider> = match chain {
        ChainConfig::Bitcoind(rpc) => Box::new(
            konsensus_chain::BitcoindProvider::new(rpc.clone())
                .map_err(|e| refuse(format!("Bitcoin Core settings: {e}")))?,
        ),
        ChainConfig::Electrum(server) => Box::new(
            konsensus_chain::ElectrumProvider::new(server.clone())
                .map_err(|e| refuse(format!("Electrum settings: {e}")))?,
        ),
        _ => return Err(refuse("only Bitcoin Core or Electrum can be checked")),
    };
    let check = async {
        let genesis = provider
            .get_block_header(0)
            .await
            .map_err(|e| refuse(format!("could not read the source's genesis block ({e})")))?;
        let hash: BlockHash = genesis
            .hash
            .parse()
            .map_err(|_| refuse("the source returned an invalid genesis block hash"))?;
        let expected = bitcoin::blockdata::constants::genesis_block(network).block_hash();
        if hash != expected {
            let found = network_of_genesis(hash).map_or("an unknown network", network_name);
            return Err(refuse(format!(
                "the source is on {found} but [lightning] network is {}",
                network_name(network)
            )));
        }
        let height = provider
            .get_block_height()
            .await
            .map_err(|e| refuse(format!("could not read the source's height ({e})")))?;
        if !provider.is_synced().await {
            return Err(refuse(format!(
                "the source is still synchronizing (height {height}); switch once it has caught up"
            )));
        }
        Ok(height)
    };
    tokio::time::timeout(SOURCE_CHECK_TIMEOUT, check)
        .await
        .map_err(|_| {
            refuse(format!(
                "the source did not answer within {} seconds",
                SOURCE_CHECK_TIMEOUT.as_secs()
            ))
        })?
}

// ── Line-level edits ─────────────────────────────────────────────────────
//
// Only the `[chain]` table (and two `[lightning]` keys) change; comments and
// layout elsewhere stay. Every edit is verified afterwards by comparing the
// parsed result with the parsed original plus the intended change.

/// `chain` for `[chain]`, `[[peers]]` for an array-of-tables header.
fn header(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[[") {
        return Some(format!("[[{}]]", rest.split("]]").next()?.trim()));
    }
    let rest = trimmed.strip_prefix('[')?;
    Some(rest.split(']').next()?.trim().to_string())
}

fn key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with('[') {
        return None;
    }
    let (key, _) = trimmed.split_once('=')?;
    Some(key.trim().trim_matches('"'))
}

/// Lines `[start, end)` of table `name`: its header through its last key line.
fn table_lines(lines: &[&str], name: &str) -> Result<Option<(usize, usize)>> {
    let headers: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| header(line).map(|h| (i, h)))
        .collect();
    let mut matching = headers.iter().filter(|(_, h)| h == name);
    let Some(&(start, _)) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(refuse(format!(
            "the config has more than one [{name}] table"
        )));
    }
    let mut end = headers
        .iter()
        .map(|(i, _)| *i)
        .find(|i| *i > start)
        .unwrap_or(lines.len());
    // Blank and comment lines before the next table belong to it.
    while end > start + 1 && {
        let t = lines[end - 1].trim();
        t.is_empty() || t.starts_with('#')
    } {
        end -= 1;
    }
    Ok(Some((start, end)))
}

fn require_table(lines: &[&str], name: &str) -> Result<(usize, usize)> {
    table_lines(lines, name)?.ok_or_else(|| {
        refuse(format!(
            "the config has no [{name}] table header this command can edit; edit it by hand (docs/CHAIN-SOURCE.md)"
        ))
    })
}

fn join(lines: Vec<String>, trailing_newline: bool) -> String {
    let mut text = lines.join("\n");
    if trailing_newline {
        text.push('\n');
    }
    text
}

/// Replace the whole `[chain]` table with `chain`.
fn replace_chain(text: &str, chain: &ChainConfig) -> Result<String> {
    let lines: Vec<&str> = text.lines().collect();
    let (start, end) = require_table(&lines, "chain")?;
    let body =
        toml::to_string(chain).map_err(|_| refuse("could not render the new [chain] table"))?;
    let mut out: Vec<String> = lines[..start].iter().map(|l| l.to_string()).collect();
    out.push("[chain]".into());
    out.extend(body.lines().map(str::to_string));
    out.extend(lines[end..].iter().map(|l| l.to_string()));
    Ok(join(out, text.ends_with('\n')))
}

/// Within table `name`, drop the lines setting `remove`, then put `insert`
/// lines right after the header.
fn edit_table(text: &str, name: &str, remove: &[&str], insert: &[String]) -> Result<String> {
    let lines: Vec<&str> = text.lines().collect();
    let (start, end) = require_table(&lines, name)?;
    let mut out: Vec<String> = lines[..=start].iter().map(|l| l.to_string()).collect();
    out.extend(insert.iter().cloned());
    out.extend(
        lines[start + 1..end]
            .iter()
            .filter(|l| !key(l).is_some_and(|k| remove.contains(&k)))
            .map(|l| l.to_string()),
    );
    out.extend(lines[end..].iter().map(|l| l.to_string()));
    Ok(join(out, text.ends_with('\n')))
}

fn parse_table(text: &str) -> Result<toml::Table> {
    // Parser errors quote source lines, which may hold secrets: never attach them.
    toml::from_str(text).map_err(|_| refuse("the config is not valid TOML"))
}

/// The edited text must parse to exactly the original plus `change`.
fn verify_edit(
    original: &str,
    edited: &str,
    change: impl FnOnce(&mut toml::Table),
) -> Result<NodeConfig> {
    let mut expected = parse_table(original)?;
    change(&mut expected);
    if parse_table(edited)? != expected {
        return Err(refuse(
            "the config layout is not one this command can edit safely; edit it by hand (docs/CHAIN-SOURCE.md)",
        ));
    }
    let config: NodeConfig =
        toml::from_str(edited).map_err(|_| refuse("the edited config would not load"))?;
    config
        .validate()
        .map_err(|e| refuse(format!("the edited config would not validate ({e})")))?;
    Ok(config)
}

/// The switch: new `[chain]`, and LDK's unused Esplora URLs cleared the way a
/// fresh owned-tip init writes them.
fn switch_text(
    original: &str,
    config: &NodeConfig,
    chain: &ChainConfig,
) -> Result<(String, NodeConfig)> {
    let mut edited = replace_chain(original, chain)?;
    let ldk = matches!(config.lightning, LightningConfig::Ldk { .. });
    if ldk {
        // The credentials belong to the paid Esplora being left: LDK builds
        // its authenticated transport from them before it looks at [chain].
        edited = edit_table(
            &edited,
            "lightning",
            &["esplora_url", "esplora_url_fallback", "credentials_file"],
            &["esplora_url = \"\"".to_string()],
        )?;
    }
    let chain_value = toml::Value::try_from(chain)
        .map_err(|_| refuse("could not render the new [chain] table"))?;
    let new = verify_edit(original, &edited, |table| {
        table.insert("chain".into(), chain_value);
        if ldk {
            if let Some(toml::Value::Table(lightning)) = table.get_mut("lightning") {
                lightning.insert("esplora_url".into(), toml::Value::String(String::new()));
                lightning.remove("esplora_url_fallback");
                lightning.remove("credentials_file");
            }
        }
    })?;
    Ok((edited, new))
}

fn accept_text(original: &str) -> Result<(String, NodeConfig)> {
    let edited = edit_table(
        original,
        "chain",
        &["accept_third_party_tip"],
        &["accept_third_party_tip = true".to_string()],
    )?;
    let new = verify_edit(original, &edited, |table| {
        if let Some(toml::Value::Table(chain)) = table.get_mut("chain") {
            chain.insert("accept_third_party_tip".into(), toml::Value::Boolean(true));
        }
    })?;
    Ok((edited, new))
}

/// `konsensus.toml.before-chain-tip-20261108T170000Z`, mode 0600, never
/// overwritten. Written to a temporary name and fsynced first, then linked
/// into place, so a failed write never leaves a partial file under that name.
fn write_backup(config_path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    let name = config_path
        .file_name()
        .context("config path has no file name")?
        .to_string_lossy();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = config_path.with_file_name(format!("{name}.before-chain-tip-{stamp}"));
    let temp = config_path.with_file_name(format!(
        ".{name}.before-chain-tip-{stamp}.{}.tmp",
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        // A hard link fails if the name exists: an earlier backup is never replaced.
        std::fs::hard_link(&temp, &backup)
    });
    let _ = std::fs::remove_file(&temp);
    written.map_err(|e| {
        refuse(format!(
            "could not write the backup {} ({e}); try again in a second",
            backup.display()
        ))
    })?;
    Ok(backup)
}

fn had_esplora_credentials(config: &NodeConfig) -> bool {
    matches!(
        config.lightning,
        LightningConfig::Ldk {
            credentials_file: Some(_),
            ..
        }
    ) || matches!(
        config.chain,
        ChainConfig::Esplora {
            credentials_file: Some(_),
            ..
        }
    )
}

/// The chain-source settings embedded LDK checks at start before any network
/// use, with the same constructors in the same order: an Esplora credentials
/// file builds the authenticated transport from `esplora_url` first, then
/// Core or Electrum is built from `[chain]`. A config that fails here would
/// not start, so it is never written.
fn ldk_chain_source_preflight(config: &NodeConfig) -> Result<()> {
    let LightningConfig::Ldk {
        esplora_url,
        esplora_url_fallback,
        credentials_file,
        ..
    } = &config.lightning
    else {
        return Ok(());
    };
    let unusable = |e: &dyn std::fmt::Display| {
        refuse(format!(
            "embedded Lightning could not start from the edited config ({e})"
        ))
    };
    if let Some(file) = credentials_file {
        let auth =
            konsensus_chain::bearer::BearerAuth::from_file(file).map_err(|e| unusable(&e))?;
        konsensus_chain::bearer::BearerFailover::new(
            auth,
            esplora_url,
            esplora_url_fallback.iter().cloned().collect(),
        )
        .map_err(|e| unusable(&e))?;
    }
    match &config.chain {
        ChainConfig::Bitcoind(rpc) => {
            konsensus_chain::BitcoindProvider::new(rpc.clone()).map_err(|e| unusable(&e))?;
        }
        ChainConfig::Electrum(server) => {
            konsensus_chain::ElectrumProvider::new(server.clone()).map_err(|e| unusable(&e))?;
        }
        _ => return Err(refuse("the edited config does not select Core or Electrum")),
    }
    Ok(())
}

/// Take the node's state lock (`STATE_GENERATION.lock` beside the recovery
/// phrase) without waiting. A running node holds it for its whole life.
fn hold_state_lock(config: &NodeConfig) -> Result<Option<std::fs::File>> {
    let data_dir = config
        .identity
        .mnemonic_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = data_dir.join("STATE_GENERATION.lock");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
    {
        Ok(file) => file,
        // Never started from this directory: nothing holds it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refuse(format!("could not open {} ({e})", path.display()))),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(refuse(
            "the node is running (its state lock is held). Stop it first",
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(refuse(format!(
            "could not check the node's state lock ({e})"
        ))),
    }
}

/// Refuse when something answers on the node's own API or peer address.
async fn refuse_if_listening(config: &NodeConfig) -> Result<()> {
    for (what, addr) in [
        ("API", config.api.listen_addr),
        ("peer", config.network.listen_addr),
    ] {
        let mut target = addr;
        if target.ip().is_unspecified() {
            target.set_ip(match target {
                std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
                std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
            });
        }
        let probe = tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(target),
        )
        .await;
        if matches!(probe, Ok(Ok(_))) {
            return Err(refuse(format!(
                "something answers on the node's {what} address {target}; stop the node first"
            )));
        }
    }
    Ok(())
}

/// One line on where the tip comes from, for `chain-tip` without an action.
pub(crate) fn describe(config: &NodeConfig) -> String {
    if let Some(found) = explorer_default(config) {
        return format!(
            "third_party, explorer_default: a public explorer this node never explicitly accepted ({})",
            found.describe()
        );
    }
    let host = |url: &str| {
        reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "an invalid URL".into())
    };
    match &config.chain {
        ChainConfig::Bitcoind(rpc) => format!(
            "owned tip: Bitcoin Core RPC at {}:{} (own_node)",
            rpc.rpc_host, rpc.rpc_port
        ),
        ChainConfig::Electrum(server) => match server.operator {
            konsensus_chain::ElectrumOperator::Own => format!(
                "owned tip: Electrum server {} you declared as yours (own_node)",
                host(
                    &server
                        .server_url
                        .replacen("ssl://", "https://", 1)
                        .replacen("tcp://", "http://", 1)
                )
            ),
            konsensus_chain::ElectrumOperator::ThirdParty => {
                "third_party: an Electrum server not declared as yours".into()
            }
        },
        ChainConfig::Esplora {
            api_url,
            accept_third_party_tip,
            ..
        } => {
            let accepted = if *accept_third_party_tip {
                ", accepted (accept_third_party_tip = true)"
            } else {
                ""
            };
            let public = if public_explorer_host(api_url).is_some() {
                "public "
            } else {
                ""
            };
            format!(
                "third_party: {public}Esplora at {}{accepted}",
                host(api_url)
            )
        }
        ChainConfig::Mock => "mock: no chain source (simulated data)".into(),
    }
}

/// `konsensus chain-tip`.
pub async fn run(args: ChainTipArgs) -> Result<()> {
    let request = args.request()?;
    let path = crate::owner_cmd::absolute_config_path(&args.config)?;
    if matches!(request, Request::Show) {
        let config = NodeConfig::load(&path)?;
        println!("chain tip: {}", describe(&config));
        if let Some(found) = explorer_default(&config) {
            println!(
                "{}",
                found
                    .warning()
                    .replace("<config>", &path.display().to_string())
            );
        }
        return Ok(());
    }
    crate::seed_cmd::refuse_if_node_running(&path)?;
    let original = std::fs::read_to_string(&path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let config =
        NodeConfig::load(&path).map_err(|e| refuse(format!("the config does not load ({e})")))?;
    // Held until the new file is in place, so the node cannot start meanwhile.
    let _state_lock = hold_state_lock(&config)?;
    refuse_if_listening(&config).await?;

    let (edited, summary) = match request {
        Request::Show => unreachable!("handled above"),
        Request::Accept => {
            let ChainConfig::Esplora {
                api_url,
                accept_third_party_tip,
                ..
            } = &config.chain
            else {
                return Err(refuse(format!(
                    "[chain] backend is {}, not esplora; there is no explorer to accept",
                    config.chain.backend_name()
                )));
            };
            if *accept_third_party_tip {
                println!(
                    "[chain] already records accept_third_party_tip = true; nothing was changed."
                );
                return Ok(());
            }
            let (edited, _) = accept_text(&original)?;
            let host = public_explorer_host(api_url).unwrap_or("your Esplora");
            (
                edited,
                format!(
                    "Recorded accept_third_party_tip = true in [chain]. The node keeps reading {host} \
                     as a third_party tip and no longer warns at start."
                ),
            )
        }
        Request::Switch(source) => {
            match (&config.chain, &config.lightning) {
                (ChainConfig::Esplora { .. }, _) | (ChainConfig::Mock, LightningConfig::Ldk { .. }) => {}
                (chain, _) => {
                    return Err(refuse(format!(
                        "[chain] backend is {}; this command moves an explorer-backed node to a tip you own",
                        chain.backend_name()
                    )))
                }
            }
            let network = configured_network(&config.lightning).ok_or_else(|| {
                refuse("[lightning] states no known Bitcoin network (LDK or CLN `network`), so the new source cannot be checked")
            })?;
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let chain = owned_chain(source, network, home)?;
            let height = check_source(&chain, network).await?;
            let (edited, new) = switch_text(&original, &config, &chain)?;
            if explorer_default(&new).is_some() {
                return Err(refuse(
                    "the edited config would still read a public explorer",
                ));
            }
            ldk_chain_source_preflight(&new)?;
            let what = describe(&new);
            let credentials_note = if had_esplora_credentials(&config) {
                "\nThe paid Esplora `credentials_file` setting was removed with it; \
                 the credentials file itself was not touched."
            } else {
                ""
            };
            let source_note = if matches!(chain, ChainConfig::Electrum(_)) {
                "\nElectrum reported a tip; whether that tip is current is not checked. \
                 Your Electrum server should itself be backed by a Bitcoin Core you control; \
                 this is not checked either."
            } else {
                "\nBitcoin Core reported initial block download finished and blocks equal to headers."
            };
            (
                edited,
                format!(
                    "Chain tip is now {what}. The source answered on {} at height {height}.{source_note}\n\
                     Embedded Lightning uses the same source; its Esplora URLs were cleared.{credentials_note}",
                    network_name(network)
                ),
            )
        }
    };

    // The source check can take a while: replace only the bytes that were checked.
    let current = std::fs::read(&path)
        .map_err(|e| refuse(format!("could not re-read {} ({e})", path.display())))?;
    if current != original.as_bytes() {
        return Err(refuse(format!(
            "{} changed while the source was checked; run the command again",
            path.display()
        )));
    }
    let backup = write_backup(&path, &current)?;
    NodeConfig::write_atomic(&path, edited.as_bytes()).map_err(|e| {
        anyhow::anyhow!("{e:#}. The previous config is kept at {}", backup.display())
    })?;
    println!("{summary}");
    println!("Previous config kept at {}", backup.display());
    println!(
        "To undo: stop the node and copy that file back over {}.",
        path.display()
    );
    println!("Start the node again for the change to take effect.");
    Ok(())
}

#[cfg(test)]
#[path = "../tests/chain_tip_cmd.rs"]
mod tests;
