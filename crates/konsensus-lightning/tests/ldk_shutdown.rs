//! L0e — verify the new `LightningProvider::shutdown()` trait method
//! has the documented behavior:
//!
//! 1. The trait default is a no-op `Ok(())` — non-LDK providers (LND
//!    gRPC, mock, void) get this for free without overriding.
//! 2. The LDK provider overrides it to call `node.stop()` on a blocking
//!    pool thread, which is the path that actually fsyncs
//!    `ChannelMonitor` updates before runtime teardown.
//!
//! Validating (2) end-to-end requires a live LDK node attached to
//! regtest, which would gate this test on the `ldk-integration-test`
//! feature. Instead, this test asserts the *trait surface* — the
//! signature, the default, and that the override compiles — and leaves
//! the LDK end-to-end exercise for the integration suite that runs
//! against bitcoind+electrsd.

use async_trait::async_trait;
use konsensus_core::traits::lightning::{
    ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails,
};

/// Minimal stand-in provider that uses ALL trait defaults — proves the
/// `shutdown` default is `Ok(())` without any explicit impl.
struct DefaultProvider;

#[async_trait]
impl LightningProvider for DefaultProvider {
    async fn create_invoice(
        &self,
        _amount_msat: u64,
        _description: &str,
        _expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Err(LightningError::Backend("default-provider".into()))
    }
    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Backend("default-provider".into()))
    }
    async fn get_payment_status(
        &self,
        _payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::Backend("default-provider".into()))
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    // Intentionally NO `shutdown` override — must use trait default.
    // Intentionally NO `list_channels` override either, just to show
    // the trait's defaults compose.
}

#[tokio::test]
async fn trait_default_shutdown_is_ok() {
    let p: Box<dyn LightningProvider> = Box::new(DefaultProvider);
    let result = p.shutdown().await;
    assert!(
        result.is_ok(),
        "L0e: trait default for shutdown() must be Ok(()) so non-LDK \
         providers (LND, mock, void) inherit it without override"
    );
}

#[tokio::test]
async fn list_channels_default_still_works_alongside_shutdown_default() {
    let p = DefaultProvider;
    // Sanity: another defaulted method still composes — no accidental
    // breakage from adding shutdown to the trait.
    assert!(
        <DefaultProvider as LightningProvider>::list_channels(&p)
            .await
            .map(|v: Vec<ChannelInfo>| v.is_empty())
            .unwrap_or(false)
    );
}
