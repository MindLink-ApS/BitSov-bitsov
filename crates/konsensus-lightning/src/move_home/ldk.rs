use super::*;

/// Only constructed by the owner-console maintenance command (or regtest).
pub struct LdkBackend<'a> {
    pub node: &'a ldk_node::Node,
}
impl Backend for LdkBackend<'_> {
    fn snapshot(&self) -> Result<Snapshot> {
        let (balances, pending_monitor_events) = self.node.move_home_balances()?;
        let peers = self.node.list_peers();
        let closing = self.node.move_home_closing_channels();
        let (minimum, normal) = self.node.move_home_close_fee_rates();
        let mut estimated_close_fee_min_sats = 0u64;
        let mut estimated_close_fee_max_sats = 0u64;
        for ch in self.node.list_channels().iter().filter(|ch| ch.is_outbound) {
            estimated_close_fee_min_sats =
                estimated_close_fee_min_sats.saturating_add(minimum.saturating_mul(200));
            estimated_close_fee_max_sats = estimated_close_fee_max_sats.saturating_add(
                normal
                    .saturating_mul(200)
                    .saturating_add(ch.config.force_close_avoidance_max_fee_satoshis),
            );
        }
        Ok(Snapshot {
            estimated_close_fee_min_sats,
            estimated_close_fee_max_sats,
            unresolved_local_spends: self.node.local_spend_reservations().len(),
            unreadable_local_spends: self.node.local_spend_unreadable_rows(),
            pending_monitor_events,
            channels: self
                .node
                .list_channels()
                .into_iter()
                .map(|ch| Channel {
                    id: ch.user_channel_id.to_string(),
                    peer: ch.counterparty_node_id.to_string(),
                    shutting_down: closing.contains(&ch.user_channel_id),
                    connected: peers
                        .iter()
                        .any(|p| p.node_id == ch.counterparty_node_id && p.is_connected),
                })
                .collect(),
            onchain_sats: balances.total_onchain_balance_sats,
            spendable_sats: balances.spendable_onchain_balance_sats,
            lightning_sats: balances.total_lightning_balance_sats,
            lightning_claims: balances.lightning_balances.len(),
            pending_sweeps: balances.pending_balances_from_channel_closures.len(),
            anchor_reserve_sats: balances.total_anchor_channels_reserve_sats,
            claim_details: balances
                .lightning_balances
                .iter()
                .map(|b| format!("{b:?}"))
                .chain(
                    balances
                        .pending_balances_from_channel_closures
                        .iter()
                        .map(|b| format!("{b:?}")),
                )
                .collect(),
        })
    }
    fn close(&self, channel: &Channel, force: bool) -> Result<()> {
        let id = ldk_node::UserChannelId(channel.id.parse()?);
        let peer = channel.peer.parse()?;
        self.node.close_channel_for_move_home(&id, peer, force)?;
        Ok(())
    }
    fn prepare_sweep(&self, plan: &Plan) -> Result<Sweep> {
        let (tx, fee_sats) = self.node.prepare_move_home(
            &plan.address()?,
            bitcoin::FeeRate::from_sat_per_vb(plan.fee_rate_sat_vb).ok_or("invalid fee rate")?,
        )?;
        let sweep = Sweep {
            transaction: bitcoin::consensus::encode::serialize_hex(&tx),
            fee_sats,
        };
        sweep.validate(plan)?;
        Ok(sweep)
    }
    fn broadcast(&mut self, sweep: &Sweep, plan: &Plan) -> Result<()> {
        sweep.validate(plan)?;
        let tx = sweep.tx()?;
        self.node
            .replay_move_home(&tx, &plan.address()?, sweep.fee_sats)
            .map_err(|error| format!("Sweep {}: {error}", tx.compute_txid()))?;
        Ok(())
    }
    fn confirmations(&self, sweep: &Sweep) -> Result<u32> {
        Ok(self
            .node
            .move_home_confirmations(sweep.tx()?.compute_txid()))
    }
}
