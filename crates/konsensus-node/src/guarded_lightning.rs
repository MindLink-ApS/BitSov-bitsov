//! One admission boundary for API, peer invoices, and automatic channel workers.
//! Already admitted work, settlement reconciliation, closes and shutdown pass through.
use crate::safety::DiskGuard;
use async_trait::async_trait;
use futures::stream::BoxStream;
use konsensus_core::traits as super_traits;
use konsensus_core::traits::lightning::*;
use std::sync::Arc;

#[cfg(test)]
#[path = "../../konsensus-api/tests/common/mod.rs"]
mod test_common;

#[cfg(test)]
#[path = "tests/balance_breakdown.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/funding_fees.rs"]
mod funding_tests;

#[cfg(test)]
#[path = "tests/hub_only_channels.rs"]
mod hub_only_tests;

/// Who new channels may be opened with, in either direction. Selected for this
/// invocation, never loaded from configuration.
#[derive(Clone, Debug, Default)]
pub enum ChannelPeers {
    #[default]
    Any,
    /// `--remote-unlock`: nothing watches this node's channels while it sits
    /// locked (no watchtower yet), so only the configured hub/LSP node ids qualify.
    HubOnly(Arc<[String]>),
}

impl ChannelPeers {
    /// Hub-only policy from `[lightning.liquidity] providers`, the configured
    /// LSP/hub set. Other backends configure no hub, so every peer is refused.
    pub fn hub_only(lightning: &crate::config::LightningConfig) -> anyhow::Result<Self> {
        let crate::config::LightningConfig::Ldk { liquidity, lsps2_service, .. } = lightning else {
            return Ok(Self::HubOnly(Arc::from([])));
        };
        anyhow::ensure!(
            !lsps2_service.enabled,
            "{HUB_ONLY_WHILE_LOCKABLE}: lsps2_service opens channels to any client; disable it to start with --remote-unlock"
        );
        Ok(Self::HubOnly(
            liquidity.providers.iter().map(|p| p.node_id.to_ascii_lowercase()).collect(),
        ))
    }

    /// The allowlist handed to the Lightning backend, if any.
    pub fn allowlist(&self) -> Option<Vec<String>> {
        match self {
            Self::Any => None,
            Self::HubOnly(hubs) => Some(hubs.to_vec()),
        }
    }

    fn check(&self, peer_pubkey: &str) -> Result<(), LightningError> {
        match self {
            Self::HubOnly(hubs) if !hubs.iter().any(|hub| hub.eq_ignore_ascii_case(peer_pubkey)) => {
                tracing::warn!(peer = %peer_pubkey, code = HUB_ONLY_WHILE_LOCKABLE, "refused channel open to a non-hub peer");
                Err(LightningError::PaymentNotDispatched(HUB_ONLY_WHILE_LOCKABLE.into()))
            }
            _ => Ok(()),
        }
    }
}

pub struct GuardedLightning {
    pub inner: Arc<dyn LightningProvider>,
    pub disk: Arc<DiskGuard>,
    pub channel_peers: ChannelPeers,
    // Drop after the provider; cloned handles must retain the directory lease.
    pub _state_guard: Arc<std::fs::File>,
}

#[async_trait]
impl LightningProvider for GuardedLightning {
    fn chain_sync_status(&self) -> Option<konsensus_core::traits::lightning::ChainSyncStatus> {
        self.inner.chain_sync_status()
    }

    fn disk_status(&self) -> Option<DiskStatus> {
        Some(self.disk.refresh())
    }
    async fn money_ready(&self) -> bool {
        self.inner.money_ready().await
    }
    async fn readiness(&self) -> LightningReadiness {
        self.inner.readiness().await
    }
    fn liquidity_info(&self) -> super_traits::liquidity::LiquidityInfo {
        self.inner.liquidity_info()
    }
    async fn quote_liquidity(
        &self,
        owner: &str,
        gross_msat: u64,
        max_fee_msat: u64,
    ) -> Result<super_traits::liquidity::LiquidityQuote, LightningError> {
        self.disk.check()?;
        self.inner
            .quote_liquidity(owner, gross_msat, max_fee_msat)
            .await
    }
    fn liquidity_quote(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<super_traits::liquidity::LiquidityQuote, LightningError> {
        self.inner.liquidity_quote(owner, id)
    }
    async fn accept_liquidity(&self, owner: &str, id: &str) -> Result<Invoice, LightningError> {
        self.disk.check()?;
        self.inner.accept_liquidity(owner, id).await
    }
    async fn is_funding_payment(&self, hash: &str) -> Result<bool, LightningError> {
        self.inner.is_funding_payment(hash).await
    }
    async fn liquidity_receipt(
        &self,
        hash: &str,
    ) -> Result<Option<super_traits::liquidity::LiquidityReceipt>, LightningError> {
        self.inner.liquidity_receipt(hash).await
    }
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.disk.check()?;
        self.inner
            .create_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn create_stateless_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.disk.check()?;
        self.inner
            .create_stateless_invoice(amount_msat, description, expiry_secs)
            .await
    }
    fn routing_fee_policy(&self) -> RoutingFeePolicy {
        self.inner.routing_fee_policy()
    }
    async fn keysend_with_fee_limit(
        &self,
        dest: &str,
        amount: u64,
        memo: Option<&str>,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.disk.check()?;
        self.inner
            .keysend_with_fee_limit(dest, amount, memo, max_fee_msat)
            .await
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.disk.check()?;
        self.inner.pay_invoice(bolt11).await
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.disk.check()?;
        self.inner
            .pay_invoice_with_fee_limit(bolt11, max_fee_msat)
            .await
    }
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(payment_hash).await
    }
    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        self.inner.outgoing_payment_updates()
    }
    async fn verify_payment(&self, payment_hash: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.verify_payment(payment_hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }
    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        // Wallet observations remain available when disk admission blocks new work.
        self.inner.get_balance_breakdown().await
    }
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        self.inner.list_payments(limit).await
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        self.inner.list_channels().await
    }
    async fn is_available(&self) -> bool {
        self.inner.is_available().await
    }
    async fn wallet_sync(&self) -> WalletSync {
        self.inner.wallet_sync().await
    }
    async fn shutdown(&self) -> Result<(), LightningError> {
        self.inner.shutdown().await
    }
    async fn is_payment_capable(&self) -> bool {
        self.inner.is_payment_capable().await
    }
    async fn keysend(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        self.disk.check()?;
        self.inner.keysend(dest_pubkey, amount_msat, memo).await
    }
    async fn keysend_with_binding(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        binding_tlv: &[u8],
    ) -> Result<PaymentDetails, LightningError> {
        self.disk.check()?;
        self.inner
            .keysend_with_binding(dest_pubkey, amount_msat, binding_tlv)
            .await
    }
    async fn watch_inbound_keysend(
        &self,
    ) -> Result<BoxStream<'static, InboundPayment>, LightningError> {
        self.inner.watch_inbound_keysend().await
    }
    fn inbound_keysend_stream_requires_reconciliation(&self) -> bool {
        self.inner.inbound_keysend_stream_requires_reconciliation()
    }
    async fn create_hodl_invoice(
        &self,
        payment_hash: &str,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        self.disk.check()?;
        self.inner
            .create_hodl_invoice(payment_hash, amount_msat, description, expiry_secs)
            .await
    }
    async fn settle_hodl_invoice(&self, preimage: &str) -> Result<(), LightningError> {
        self.inner.settle_hodl_invoice(preimage).await
    }
    async fn cancel_hodl_invoice(&self, payment_hash: &str) -> Result<(), LightningError> {
        self.inner.cancel_hodl_invoice(payment_hash).await
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        self.inner.get_node_pubkey().await
    }
    async fn get_funding_address(&self) -> Option<String> {
        self.inner.get_funding_address().await
    }
    async fn send_onchain(
        &self,
        address: &str,
        amount_sats: u64,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        self.inner
            .send_onchain(address, amount_sats, fee_rate_sat_per_vb)
            .await
    }
    async fn open_channel(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        self.channel_peers.check(peer_pubkey)?;
        self.disk.check()?;
        self.inner
            .open_channel(
                peer_pubkey,
                peer_addr,
                amount_sats,
                announce,
                fee_rate_sat_per_vb,
            )
            .await
    }
    async fn open_channel_with_status(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.channel_peers.check(peer_pubkey)?;
        self.disk.check()?;
        self.inner
            .open_channel_with_status(
                peer_pubkey,
                peer_addr,
                amount_sats,
                announce,
                fee_rate_sat_per_vb,
            )
            .await
    }
    async fn funding_fee_quote(
        &self,
        options: FundingOptions,
    ) -> Result<FundingFeeEstimate, LightningError> {
        self.disk.check()?;
        self.inner.funding_fee_quote(options).await
    }
    async fn open_channel_with_funding(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        options: FundingOptions,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.channel_peers.check(peer_pubkey)?;
        self.disk.check()?;
        self.inner
            .open_channel_with_funding(peer_pubkey, peer_addr, amount_sats, announce, options)
            .await
    }
    async fn close_channel(
        &self,
        channel_id: &str,
        force: bool,
    ) -> Result<Option<String>, LightningError> {
        self.inner.close_channel(channel_id, force).await
    }
}
