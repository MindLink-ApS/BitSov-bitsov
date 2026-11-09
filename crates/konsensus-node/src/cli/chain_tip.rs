//! `konsensus chain-tip`: show where the chain tip comes from and whether it
//! is a public explorer the node never explicitly accepted.
//!
//! Read-only. It loads the config and prints; it never writes the config or
//! any other file. Moving to an owned tip, or accepting the explorer, is a
//! hand edit described in docs/CHAIN-SOURCE.md.

use std::path::PathBuf;

use anyhow::Result;

use crate::chain_tip::{explorer_default, public_explorer_host};
use crate::config::{ChainConfig, NodeConfig};

#[derive(clap::Args, Debug)]
pub struct ChainTipArgs {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "konsensus.toml")]
    pub config: PathBuf,
}

/// One line on where the tip comes from. Hosts only, never URLs.
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

/// `konsensus chain-tip`: print the source and, for an explorer default, the
/// same guidance the node logs at start. Changes nothing.
pub fn run(args: ChainTipArgs) -> Result<()> {
    let path = crate::owner_cmd::absolute_config_path(&args.config)?;
    let config = NodeConfig::load(&path)?;
    println!("chain tip: {}", describe(&config));
    if let Some(found) = explorer_default(&config) {
        println!("{}", found.warning());
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/chain_tip_cmd.rs"]
mod tests;
