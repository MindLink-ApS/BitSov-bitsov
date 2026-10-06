//! Local owner-console maintenance. No HTTP handler or device-grant authority.
use crate::config::{ChainConfig, LightningConfig, NodeConfig};
use anyhow::{Context, Result};
use clap::Args;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_lightning::{
    move_home::{Backend, Job, LdkBackend, Plan, Progress, Snapshot, JOURNAL_FILE},
    LdkConfig, LdkProvider,
};
use std::{
    collections::BTreeSet,
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[derive(Args)]
pub struct MoveHomeArgs {
    #[arg(short, long, default_value = "konsensus.toml")]
    pub config: PathBuf,
    /// The ONLY destination of every migration sweep. Must match the node network.
    #[arg(long)]
    pub destination: String,
    /// Sweep rate in sat/vB (1..=10000). Exact amount/fee needs separate console consent.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=10000))]
    pub fee_rate: u64,
    /// Begin/resume after a destination-bound owner-console confirmation. Default: preview.
    #[arg(long)]
    pub confirm: bool,
    /// Named user_channel_id to force-close after a prior cooperative attempt; disconnected peers only.
    #[arg(long, requires_all = ["confirm", "confirm_force_close"])]
    pub force_close: Vec<String>,
    /// Additional authorization gate; also requires a separate typed console confirmation.
    #[arg(long, requires = "force_close")]
    pub confirm_force_close: bool,
    /// Read encrypted-seed password from inherited descriptor (otherwise prompt on terminal).
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..))]
    pub password_fd: Option<i32>,
}

/// Never accept stdin, a pipe, an API bearer, or a device budget as consent.
fn owner_confirm(expected: &str) -> Result<()> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("move-home requires the owner's controlling console (/dev/tty)")?;
    writeln!(tty, "Type exactly to authorize:\n{expected}")?;
    tty.flush()?;
    let mut response = String::new();
    std::io::BufReader::new(&tty).read_line(&mut response)?;
    validate_confirmation(expected, response.trim_end_matches(['\r', '\n']))
}
fn validate_confirmation(expected: &str, response: &str) -> Result<()> {
    anyhow::ensure!(
        response == expected,
        "owner confirmation did not match; no action authorized"
    );
    Ok(())
}
fn show_preview(plan: &Plan, snapshot: &Snapshot) -> Result<()> {
    println!(
        "Move home destination: {}\nNetwork: {}\nNode: {}",
        plan.destination, plan.network, plan.node_id
    );
    println!("{}", serde_json::to_string_pretty(snapshot)?);
    println!("Sweep rate: {} sat/vB. Estimated cooperative close fees paid by this node: ~{}..{} sats, at 200 vB per outbound channel using current LDK fee estimates plus the configured close-avoidance allowance. Peer negotiation, transaction size, and later fee changes affect the actual fees; this is NOT a quote or cap. Lightning balance above excludes some commitment fees and may change as HTLCs settle.", plan.fee_rate_sat_vb, snapshot.estimated_close_fee_min_sats, snapshot.estimated_close_fee_max_sats);
    println!("Channel funds/CSV delays must resolve first. Exact final sweep amount and fee will be previewed and separately confirmed on this console. Until then no destination sweep is authorized. Keep the current live data and seed until every sweep has 6 confirmations.");
    Ok(())
}

pub async fn run(args: MoveHomeArgs) -> Result<()> {
    let config = NodeConfig::load(&args.config)?;
    let LightningConfig::Ldk {
        network,
        esplora_url,
        esplora_url_fallback,
        credentials_file,
        rgs_url,
        listening_address,
        ..
    } = &config.lightning
    else {
        anyhow::bail!("move-home requires the current embedded LDK node");
    };
    // Validate destination/fee before state startup or opening any wallet.
    Plan::new(
        "validation".into(),
        network,
        &args.destination,
        args.fee_rate,
    )
    .map_err(anyhow::Error::msg)?;
    let data_dir = config
        .identity
        .mnemonic_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let storage_dir = data_dir.join("ldk");
    anyhow::ensure!(storage_dir.join("ldk_node_data.sqlite").is_file(), "move-home requires the original current live LDK store; it does not restore a backup or create a fresh wallet");
    let lease = Arc::new(crate::safety::ensure_generation(
        data_dir,
        crate::safety::STATE_GENERATION,
    )?);
    let password = if let Some(fd) = args.password_fd {
        Some(crate::password::read_password_fd(fd)?)
    } else if crate::mnemonic_crypto::is_encrypted_path(&config.identity.mnemonic_file) {
        Some(zeroize::Zeroizing::new(rpassword::prompt_password(
            "Seed password: ",
        )?))
    } else {
        None
    };
    let mnemonic = crate::mnemonic_crypto::read_mnemonic(
        &config.identity.mnemonic_file,
        password.as_deref().map(String::as_str),
    )?;
    let ldk_config = LdkConfig {
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
        storage_dir: storage_dir.clone(),
        scb_backup_dir: Some(PathBuf::from(&config.backup.scb_dir)),
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
        listening_address: listening_address.clone(),
        forward_to_private_channels: false,
    };
    // Refuse a changed plan BEFORE constructing LDK, including reconnects.
    let seed = zeroize::Zeroizing::new(konsensus_lightning::scb_restore::derive_ldk_entropy_seed(
        &mnemonic,
        Some(&config.identity.passphrase),
    )?);
    drop(password);
    // Node id is verified below after construction. Check the other immutable
    // fields by loading the journal with the identity derived from the live seed.
    let node_id =
        konsensus_lightning::move_home::node_id_from_seed(&seed).map_err(anyhow::Error::msg)?;
    let plan = Plan::new(node_id, network, &args.destination, args.fee_rate)
        .map_err(anyhow::Error::msg)?;
    let journal = storage_dir.join(JOURNAL_FILE);
    let existing = Job::load(&journal, &plan).map_err(anyhow::Error::msg)?;
    let deny_work = Arc::new(move || {
        let _lease = &lease;
        false
    });
    let provider = LdkProvider::new_for_move_home(ldk_config, deny_work).await?;
    let result = run_job(&args, &provider, plan, journal, existing).await;
    let shutdown = provider.shutdown().await;
    result?;
    shutdown?;
    Ok(())
}
async fn run_job(
    args: &MoveHomeArgs,
    provider: &LdkProvider,
    plan: Plan,
    journal: PathBuf,
    existing: Option<Job>,
) -> Result<()> {
    let node = provider.node();
    anyhow::ensure!(
        node.node_id().to_string() == plan.node_id,
        "live node identity mismatch"
    );
    tokio::task::block_in_place(|| node.sync_wallets())?;
    let mut backend = LdkBackend { node };
    show_preview(&plan, &backend.snapshot().map_err(anyhow::Error::msg)?)?;
    if let Some(job) = &existing {
        for (txid, confirmations) in job.sweep_status(&backend).map_err(anyhow::Error::msg)? {
            println!("Saved sweep {txid}: {confirmations}/6 confirmations (zero is queued/unconfirmed/unknown).");
        }
    }
    if !args.confirm {
        if let Some(job) = existing {
            println!("Existing migration to {}. Resume with --confirm, the same destination and fee rate.", job.plan().destination);
        }
        if !backend
            .snapshot()
            .map_err(anyhow::Error::msg)?
            .waiting_for_channels()
        {
            match backend.prepare_sweep(&plan) {
                Ok(sweep) => println!(
                    "Current sweep preview: {} sats to destination; {} sats fee.",
                    sweep.validate(&plan).map_err(anyhow::Error::msg)?,
                    sweep.fee_sats
                ),
                Err(e) => println!("Sweep not currently constructible: {e}. No sweep authorized."),
            }
        }
        println!("Preview only: no close or destination sweep requested. Use --confirm on the owner console to begin/resume.");
        return Ok(());
    }
    owner_confirm(&format!("MOVE HOME {}", plan.destination))?;
    let mut job = match existing {
        Some(job) => job,
        None => Job::begin(&journal, plan).map_err(anyhow::Error::msg)?,
    };
    if !args.force_close.is_empty() {
        let selected: BTreeSet<_> = args.force_close.iter().cloned().collect();
        println!("Force-close spends CURRENT live state, costs more, and may lock funds for CSV/HTLC delays. Channels: {selected:?}");
        owner_confirm(&format!(
            "FORCE CLOSE {}",
            selected.iter().cloned().collect::<Vec<_>>().join(",")
        ))?;
        job.approve_force(&selected, &backend)
            .map_err(anyhow::Error::msg)?;
    }
    loop {
        tokio::task::block_in_place(|| node.sync_wallets())
            .context("chain sync failed; migration retained, no new sweep attempted")?;
        let lock = node.onchain_operation_lock();
        let guard = lock.lock().await;
        let progress = job.advance(&mut backend).map_err(anyhow::Error::msg)?;
        match progress {
            Progress::Waiting { snapshot, close_errors } => {
                println!("Waiting for channel closes/claims (not complete): {}", serde_json::to_string(&snapshot)?);
                for error in close_errors { println!("Close pending/error: {error}"); }
            }
            Progress::SweepPreview(sweep) => {
                let amount = sweep.validate(job.plan()).map_err(anyhow::Error::msg)?;
                println!("Sweep preview: {amount} sats to {}, fee {} sats; txid {}. No change output.", job.plan().destination, sweep.fee_sats, sweep.txid().map_err(anyhow::Error::msg)?);
                owner_confirm(&format!("SEND {amount} FEE {} TO {}", sweep.fee_sats, job.plan().destination))?;
                job.approve_sweep(&sweep, &backend).map_err(anyhow::Error::msg)?;
                println!("Sweep consent saved. Broadcast/confirmation is still pending.");
            }
            Progress::Confirming { txid, confirmations } => println!("Sweep {txid}: {confirmations}/6 confirmations. Zero means queued, unconfirmed or unknown; broadcast acceptance is not assumed."),
            Progress::Complete => {
                println!("Move home complete in the current synced chain view: no channels, claims, pending sweeps or wallet balance; all migration sweeps have at least 6 confirmations. Retain the seed and live store for reorgs/late payments. Normal startup remains locked.");
                return Ok(());
            }
        }
        drop(guard);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("Paused. Keep this live store; resume the same command with --confirm."); return Ok(()); }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn consent_is_exact_and_destination_bound() {
        assert!(validate_confirmation("MOVE HOME a", "MOVE HOME b").is_err());
        assert!(validate_confirmation("MOVE HOME a", "yes").is_err());
        assert!(validate_confirmation("MOVE HOME a", "MOVE HOME a").is_ok());
        assert!(validate_confirmation("FORCE CLOSE 1", "MOVE HOME a").is_err());
    }
    #[test]
    fn force_flag_requires_separate_confirmation_flag() {
        use crate::cli::Cli;
        assert!(Cli::try_parse_from([
            "konsensus",
            "move-home",
            "--destination",
            "a",
            "--confirm",
            "--force-close",
            "1"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "konsensus",
            "move-home",
            "--destination",
            "a",
            "--confirm",
            "--force-close",
            "1",
            "--confirm-force-close"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "konsensus",
            "move-home",
            "--destination",
            "a",
            "--owner-token",
            "device-budget"
        ])
        .is_err());
    }
}
