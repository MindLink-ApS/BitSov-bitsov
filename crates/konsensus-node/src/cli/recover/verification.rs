//! The post-sweep live store is canonical and retained for normal start.
//! Only console-approved LSPS2 invoice publication and a 1-sat hub test are exposed.
use super::*;
use bitcoin::hashes::{sha256, Hash};
use konsensus_lightning::ldk::LdkConfig;
use lightning_invoice::Bolt11Invoice;

pub(super) async fn run(
    args: &RecoverArgs,
    job: &mut Job,
    chain: &dyn RecoveryChain,
    config: LdkConfig,
    seed: &[u8; 64],
) -> Result<()> {
    let hub = config
        .liquidity
        .selected()?
        .context("select the LSPS2 verification hub")?
        .clone();
    job.begin_verification(hub.node_id.clone())
        .map_err(anyhow::Error::msg)?;
    let store_id = job
        .verification()
        .context("missing verification")?
        .store_id
        .clone();
    let provider = LdkProvider::new_for_recovery_verification(config, &store_id).await?;
    let result = verify(args, job, chain, &provider, seed, &hub).await;
    let shutdown = provider.shutdown().await;
    let completed = result?;
    shutdown?;
    if let Some(checks) = completed {
        let report = job
            .finish(chain, checks)
            .await
            .map_err(anyhow::Error::msg)?;
        println!("Recovered: {}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

async fn verify(
    args: &RecoverArgs,
    job: &mut Job,
    chain: &dyn RecoveryChain,
    provider: &LdkProvider,
    seed: &[u8; 64],
    hub: &konsensus_lightning::liquidity::LspConfig,
) -> Result<Option<String>> {
    use konsensus_core::traits::lightning::PaymentStatus;
    use konsensus_lightning::recover::Verification;
    // A persisted, recovery-created live store is used on resume. Never touch backup data.
    let node = provider.node();
    node.connect(hub.node_id.parse()?, hub.address.parse()?, true)?;
    anyhow::ensure!(
        node.node_id().to_string() == job.plan().node_id,
        "verification identity mismatch"
    );
    let mut displayed_invoice = None;
    loop {
        tokio::task::block_in_place(|| node.sync_wallets())?;
        if let Some(progress) = job.resume_sweeps(chain).await.map_err(anyhow::Error::msg)? {
            println!("Revalidating approved sweep before Lightning verification: {progress:?}");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(None),
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            continue;
        }
        let mut state: Verification = job
            .verification()
            .context("verification state missing")?
            .clone();
        let invoice = state
            .invoice
            .as_ref()
            .map(|s| s.parse::<Bolt11Invoice>())
            .transpose()?;
        let mut received = false;
        for saved in state.previous_invoices.iter().chain(state.invoice.iter()) {
            let invoice: Bolt11Invoice = saved.parse()?;
            match provider
                .get_payment_status(&invoice.payment_hash().to_string())
                .await
            {
                Ok(p) => received |= p.status == PaymentStatus::Settled,
                Err(konsensus_core::traits::lightning::LightningError::PaymentNotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !received {
            if invoice.as_ref().is_none_or(|i| i.is_expired()) {
                if let Some(previous) = &invoice {
                    println!("The expired invoice may still have an in-flight payment. Confirm it failed in the paying wallet before replacing it. Both payments could settle if you fund another invoice; all issued invoices remain tracked.");
                    crate::move_home_cmd::owner_confirm(&format!(
                        "REPLACE EXPIRED INVOICE {}",
                        previous.payment_hash()
                    ))?;
                }
                let quote = provider
                    .quote_liquidity(
                        "recover-console",
                        args.self_test_funding_sats * 1000,
                        args.self_test_max_fee_sats * 1000,
                    )
                    .await?;
                println!("Fresh LSPS2 self-test: fund {} msat from another wallet; fee at most {} msat, net at least {} msat. This invoice is not paid from the recovered on-chain funds.", quote.gross_msat, quote.max_fee_msat, quote.min_net_msat);
                crate::move_home_cmd::owner_confirm(&format!(
                    "SELF TEST FUND {} FEE {} HUB {}",
                    quote.gross_msat, quote.max_fee_msat, hub.node_id
                ))?;
                let invoice = provider
                    .accept_liquidity("recover-console", &quote.quote_id)
                    .await?;
                if let Some(previous) = state.invoice.replace(invoice.bolt11) {
                    state.previous_invoices.push(previous);
                }
                job.save_verification(state.clone())
                    .map_err(anyhow::Error::msg)?;
            }
            if displayed_invoice != state.invoice {
                println!("Pay this fresh-channel funding invoice from another wallet, then leave this console running:\n{}", state.invoice.as_deref().context("invoice missing")?);
                println!("The hub may defer opening while its old close resolves. If payment fails, wait for this invoice to expire before requesting another. Ctrl-C safely pauses verification.");
                displayed_invoice = state.invoice.clone();
            }
        } else if provider.money_ready().await
            && node
                .list_channels()
                .iter()
                .any(|c| c.is_usable && c.counterparty_node_id.to_string() == hub.node_id)
        {
            // Derive a stable per-attempt preimage; journal its public payment id BEFORE send.
            // A crash before/after send therefore resumes the same payment, never a second one.
            let mut material = Zeroizing::new(seed.to_vec());
            material.extend_from_slice(state.store_id.as_bytes());
            material.extend_from_slice(&state.payment_attempt.to_be_bytes());
            let preimage =
                Zeroizing::new(blake3::derive_key("bitsov recover self-test v1", &material));
            let id = sha256::Hash::hash(preimage.as_ref()).to_string();
            if let Some(saved) = &state.payment_id {
                anyhow::ensure!(*saved == id, "self-test payment identity changed");
            } else {
                crate::move_home_cmd::owner_confirm(&format!(
                    "SELF TEST SEND 1 SAT TO {}",
                    hub.node_id
                ))?;
                state.payment_id = Some(id.clone());
                job.save_verification(state.clone())
                    .map_err(anyhow::Error::msg)?;
            }
            match provider.get_payment_status(&id).await {
                Ok(payment) if payment.status == PaymentStatus::Settled => {
                    anyhow::ensure!(
                        payment.amount_msat == 1000,
                        "self-test payment amount differs"
                    );
                    return Ok(Some(format!(
                        "money_ready=true; fresh LSPS2 channel; 1-sat hub payment {id} settled"
                    )));
                }
                Ok(payment) if payment.status == PaymentStatus::Failed => {
                    crate::move_home_cmd::owner_confirm("RETRY FAILED SELF TEST")?;
                    state.payment_attempt = state
                        .payment_attempt
                        .checked_add(1)
                        .context("self-test retry limit")?;
                    state.payment_id = None;
                    job.save_verification(state).map_err(anyhow::Error::msg)?;
                }
                Ok(_) => println!("Waiting for the 1-sat self-test payment to settle."),
                Err(konsensus_core::traits::lightning::LightningError::PaymentNotFound(_)) => {
                    provider
                        .send_recovery_self_test(&hub.node_id, *preimage)
                        .map_err(anyhow::Error::msg)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("Verification paused. Keep this new live store; resume recover with the same plan. Normal start remains fenced."); return Ok(None); }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}
