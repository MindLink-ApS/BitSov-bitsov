//! Owner console only: no HTTP route, stdin consent, or backup state startup.
#[path = "recover/verification.rs"]
mod verification;
use crate::config::{ChainConfig, LightningConfig, NodeConfig};
use anyhow::{Context, Result};
use bitcoin::{bip32::Xpriv, Network};
use clap::Args;
use konsensus_chain::recovery::RecoveryChain;
use konsensus_core::traits::{chain::TrustLevel, lightning::LightningProvider};
use konsensus_lightning::{
    move_home::Plan,
    recover::{Job, Progress},
    LdkConfig, LdkProvider,
};
use konsensus_recovery::{BackupIndex, RecoveryKeys, MAX_BACKUP_BYTES};
use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct RecoverArgs {
    #[arg(short, long, default_value = "konsensus.toml")]
    pub config: PathBuf,
    /// Encrypted SCB file, read only as a public index. Never a live store.
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// Default: this seed's own on-chain wallet. Must match the network.
    #[arg(long)]
    pub destination: Option<String>,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=10000))]
    pub fee_rate: u64,
    /// Start/resume after typed owner-console consent. Default is offline preview.
    #[arg(long)]
    pub confirm: bool,
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..))]
    pub password_fd: Option<i32>,
    /// External funding invoice amount for the fresh LSPS2 self-test channel.
    #[arg(long, default_value_t = 20_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000))]
    pub self_test_funding_sats: u64,
    /// Maximum LSPS2 fee; the exact quote still requires typed console consent.
    #[arg(long, default_value_t = 2_000, value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    pub self_test_max_fee_sats: u64,
}

fn chain(config: &ChainConfig) -> Result<Box<dyn RecoveryChain>> {
    Ok(match config {
        ChainConfig::Bitcoind(rpc) => {
            Box::new(konsensus_chain::BitcoindProvider::new(rpc.clone())?)
        }
        ChainConfig::Electrum(server) => {
            Box::new(konsensus_chain::ElectrumProvider::new(server.clone())?)
        }
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
            credentials_file,
        } => {
            let mut provider = konsensus_chain::EsploraProvider::with_fallbacks(
                konsensus_chain::EsploraConfig::custom(api_url.clone(), TrustLevel::ServerTrust),
                esplora_url_fallback.iter().cloned().collect(),
            )?;
            if let Some(file) = credentials_file {
                provider =
                    provider.with_bearer(konsensus_chain::bearer::BearerAuth::from_file(file)?)?;
            }
            Box::new(provider)
        }
        ChainConfig::Mock => anyhow::bail!("recovery requires bitcoind, Electrum or Esplora"),
    })
}

pub async fn run(args: RecoverArgs) -> Result<()> {
    let config = NodeConfig::load(&args.config)?;
    let LightningConfig::Ldk {
        network,
        esplora_url,
        esplora_url_fallback,
        credentials_file,
        rgs_url,
        liquidity,
        ..
    } = &config.lightning
    else {
        anyhow::bail!("recover requires embedded LDK");
    };
    let data_dir = config
        .identity
        .mnemonic_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let storage = data_dir.join("ldk");
    let _lease = crate::safety::ensure_generation(data_dir, crate::safety::STATE_GENERATION)?;
    konsensus_lightning::recover::ensure_recovery_root(&storage).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        storage.join("recover.json").is_file(),
        "use konsensus restore into a fresh directory first"
    );
    crate::restore_fence::ensure_recovery_bound(data_dir)?;
    let password = if let Some(fd) = args.password_fd {
        Some(crate::password::read_password_fd(fd)?)
    } else if crate::mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file) {
        Some(Zeroizing::new(rpassword::prompt_password(
            "Seed password: ",
        )?))
    } else {
        None
    };
    let mnemonic = crate::mnemonic_crypto::read_mnemonic(
        &config.identity.mnemonic_file,
        password.as_deref().map(String::as_str),
    )?;
    let seed = Zeroizing::new(konsensus_lightning::scb_restore::derive_ldk_entropy_seed(
        &mnemonic,
        Some(&config.identity.passphrase),
    )?);
    let mut master = Xpriv::new_master(Network::from_str(network)?, &*seed)?;
    let ldk_key = Zeroizing::new(master.private_key.secret_bytes());
    master.private_key.non_secure_erase();
    let keys = RecoveryKeys::from_ldk_seed(&ldk_key)?;
    let index = if let Some(path) = &args.backup {
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(path)?
            .take(MAX_BACKUP_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= MAX_BACKUP_BYTES,
            "backup exceeds resource limit"
        );
        let backup_key = Zeroizing::new(
            konsensus_lightning::scb_restore::derive_scb_master_key_from_ldk_seed(&seed),
        );
        Some(BackupIndex::decrypt(&bytes, &backup_key, &keys)?)
    } else {
        None
    };
    let scripts = konsensus_lightning::recover::scripts(&keys, index.as_ref());
    anyhow::ensure!(
        !scripts.is_empty(),
        "backup has no active recoverable v2 channels"
    );
    let node_id =
        konsensus_lightning::move_home::node_id_from_seed(&seed).map_err(anyhow::Error::msg)?;
    let destination = args.destination.clone().unwrap_or(
        konsensus_lightning::recover::wallet_address(&seed, Network::from_str(network)?)
            .map_err(anyhow::Error::msg)?
            .to_string(),
    );
    let plan =
        Plan::new(node_id, network, &destination, args.fee_rate).map_err(anyhow::Error::msg)?;
    let funding = index
        .as_ref()
        .map(|i| {
            i.channels()
                .iter()
                .filter(|c| !c.archived)
                .map(|c| c.funding_outpoint)
                .collect()
        })
        .unwrap_or_default();
    println!("Recover node {} on {} to {} at {} sat/vB. {} public scripts. Backups provide historical hints only, never current balances.", plan.node_id, plan.network, plan.destination, plan.fee_rate_sat_vb, scripts.len());
    println!("The old node must be gone. The hub must be reachable and is trusted to close its latest state. In-flight HTLCs may be lost. Recovery never broadcasts a funding spend. A seed-only scan cannot prove that all old channels have closed; keep the seed for late closes.");
    if matches!(config.chain, ChainConfig::Esplora { .. }) {
        println!("Esplora recovery can cost at least {} HTTP requests per scan and reveals these scripts to the configured service; rate limits apply.", scripts.len());
    }
    // No chain source or LDK construction in preview, including a resumed job.
    if !args.confirm {
        println!("Offline preview only. Use --confirm on the owner console to connect to the configured hubs.");
        return Ok(());
    }
    anyhow::ensure!(
        !liquidity.providers.is_empty(),
        "configure the original hub(s) in lightning.liquidity.providers"
    );
    for channel in index
        .as_ref()
        .into_iter()
        .flat_map(|i| i.channels())
        .filter(|c| !c.archived)
    {
        anyhow::ensure!(
            liquidity
                .providers
                .iter()
                .any(|p| p.node_id == channel.counterparty_node_id.to_string()),
            "backup peer is not a configured hub"
        );
    }
    anyhow::ensure!(
        liquidity.selected()?.is_some(),
        "enable and select the LSPS2 hub for the post-sweep self-test"
    );
    crate::move_home_cmd::owner_confirm("OLD NODE IS GONE")?;
    crate::move_home_cmd::owner_confirm("RECOVER FROM HUB CLOSE")?;
    let mut job = Job::load_or_begin(&storage, plan, funding).map_err(anyhow::Error::msg)?;
    if job.done() {
        println!("Recovery already completed. Normal start is available.");
        return Ok(());
    }
    let chain = chain(&config.chain)?;
    let session = storage.join(format!("recover-session-{}", uuid::Uuid::new_v4()));
    let ldk_config = LdkConfig {
        tower: Default::default(),
        logging: config.logging,
        electrum: match &config.chain {
            ChainConfig::Electrum(server) => Some(server.clone()),
            _ => None,
        },
        bitcoind: match &config.chain {
            ChainConfig::Bitcoind(rpc) => Some(rpc.clone()),
            _ => None,
        },
        liquidity: Default::default(),
        lsps2_service: Default::default(),
        channel_peers: crate::guarded_lightning::ChannelPeers::from_config(&config.lightning)?
            .allowlist(),
        channel_capacity_limits: config
            .lightning
            .channel_capacity_limits()
            .expect("LDK config"),
        storage_dir: session,
        scb_backup_dir: None,
        scb_rotation_count: config.backup.rotation_count,
        mnemonic: mnemonic.to_string(),
        passphrase: Some(config.identity.passphrase.clone()).filter(|s| !s.is_empty()),
        network: network.clone(),
        esplora_url: esplora_url.clone(),
        esplora_url_fallback: esplora_url_fallback.clone(),
        esplora_sync_intervals: config.lightning.esplora_sync_intervals(),
        credentials_file: credentials_file.clone(),
        rgs_url: rgs_url.clone(),
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
    };
    let mut verification_config = ldk_config.clone();
    verification_config.storage_dir = storage;
    verification_config.liquidity = liquidity.clone();
    if job.verification().is_some() {
        return verification::run(&args, &mut job, chain.as_ref(), verification_config, &seed)
            .await;
    }
    let provider = LdkProvider::new_for_recovery(ldk_config).await?;
    let result = async {
        if args.destination.is_none() {
            anyhow::ensure!(
                provider.node().onchain_payment().new_address()?.to_string() == job.plan().destination,
                "wallet derivation mismatch"
            );
        }
        anyhow::ensure!(provider.node().node_id().to_string() == job.plan().node_id, "recovered identity differs");
        for peer in &liquidity.providers {
            // Failure retains the journal; operator can resume when hub is reachable.
            provider.node().connect(peer.node_id.parse()?, peer.address.parse()?, true)
                .context("waiting for hub; recovery remains open")?;
        }
        loop {
            tokio::task::block_in_place(|| provider.node().sync_wallets())?;
            match job.advance(chain.as_ref(), &keys, &scripts).await.map_err(anyhow::Error::msg)? {
                Progress::WaitingForHub => println!("Waiting for confirmed hub close outputs. No funds found does not mean recovery is complete."),
                Progress::SweepPreview { sweep, inputs } => {
                    let amount = sweep.validate(job.plan()).map_err(anyhow::Error::msg)?;
                    println!("Sweep {}: {amount} sats, fee {} sats, one output to {}", sweep.txid().map_err(anyhow::Error::msg)?, sweep.fee_sats, job.plan().destination);
                    crate::move_home_cmd::owner_confirm(&format!("SEND {amount} FEE {} TO {}", sweep.fee_sats, job.plan().destination))?;
                    job.approve(chain.as_ref(), sweep, inputs).await.map_err(anyhow::Error::msg)?;
                }
                Progress::Confirming { txid, confirmations } => println!("Sweep {txid}: {confirmations}/6 confirmations"),
                Progress::SelfTest => {
                    let report = konsensus_lightning::recover::self_test(&provider, &job, args.destination.is_none()).await.map_err(anyhow::Error::msg)?;
                    println!("On-chain self-test: {report}. Next: fresh LSPS2 channel and 1-sat hub payment; normal start remains fenced.");
                    return Ok(true);
                }
                Progress::Complete => return Ok(false),
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => { println!("Paused; journal remains open. Resume this command with the same plan."); return Ok(false); }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }.await;
    let shutdown = provider.shutdown().await;
    let verify = result?;
    shutdown?;
    if verify {
        verification::run(&args, &mut job, chain.as_ref(), verification_config, &seed).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[test]
    fn recover_preview_defaults_and_rejects_remote_consent() {
        let crate::cli::Command::Recover(args) =
            crate::cli::Cli::try_parse_from(["konsensus", "recover"])
                .unwrap()
                .command
        else {
            panic!("wrong command");
        };
        assert!(!args.confirm);
        assert!(args.destination.is_none());
        assert!(crate::cli::Cli::try_parse_from([
            "konsensus",
            "recover",
            "--owner-token",
            "device"
        ])
        .is_err());
        assert!(
            crate::cli::Cli::try_parse_from(["konsensus", "recover", "--fee-rate", "0"]).is_err()
        );
    }
}
