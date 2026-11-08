use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// A source whose best block is `height`, `age_secs` old. It can fail its
/// header read, and counts header reads.
struct Source {
    height: AtomicU64,
    age_secs: AtomicU64,
    fail: AtomicBool,
    synced: bool,
    header_reads: AtomicUsize,
}

impl Source {
    fn new(height: u64, age_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            height: AtomicU64::new(height),
            age_secs: AtomicU64::new(age_secs),
            fail: AtomicBool::new(false),
            synced: true,
            header_reads: AtomicUsize::new(0),
        })
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[async_trait]
impl ChainProvider for Source {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::FullValidation
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChainError::Connection("down".into()));
        }
        Ok(self.height.load(Ordering::SeqCst))
    }
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        self.header_reads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChainError::Connection("down".into()));
        }
        Ok(BlockHeader {
            height,
            hash: format!("{height:064x}"),
            timestamp: now().saturating_sub(self.age_secs.load(Ordering::SeqCst)),
            bits: 0x1d00_ffff,
        })
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte: 3.0,
        })
    }
    async fn is_tx_confirmed(&self, _: &str, _: u32) -> Result<bool, ChainError> {
        Ok(true)
    }
    async fn is_synced(&self) -> bool {
        self.synced
    }
}

#[test]
fn bound_per_network() {
    assert_eq!(max_tip_age(Some("bitcoin")), Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(max_tip_age(Some("mainnet")), Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(MAINNET_MAX_TIP_AGE, Duration::from_secs(3 * 3600));
    for network in ["testnet", "signet", "testnet4"] {
        assert_eq!(max_tip_age(Some(network)), Some(TEST_NETWORK_MAX_TIP_AGE));
    }
    assert_eq!(TEST_NETWORK_MAX_TIP_AGE, Duration::from_secs(24 * 3600));
    assert_eq!(max_tip_age(None), Some(TEST_NETWORK_MAX_TIP_AGE));
    assert_eq!(max_tip_age(Some("regtest")), None);
}

#[tokio::test]
async fn fresh_tip_is_ready() {
    let source = Source::new(900_000, 600);
    let tip = FreshTip::new(source.clone(), Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
    let header = tip.get_best_block_header().await.unwrap();
    assert_eq!((header.height, header.hash), (900_000, format!("{:064x}", 900_000)));
}

#[tokio::test]
async fn stale_tip_is_not_ready() {
    let source = Source::new(900_000, MAINNET_MAX_TIP_AGE.as_secs() + 60);
    let tip = FreshTip::new(source, Some(MAINNET_MAX_TIP_AGE));
    let error = tip.get_block_height().await.unwrap_err();
    assert!(matches!(error, ChainError::NotAvailable(ref m) if m.contains("stale")), "{error}");
    assert!(tip.get_best_block_header().await.is_err());
}

#[tokio::test]
async fn tip_at_the_bound_is_still_ready() {
    // Seconds pass between the header and the check; one minute of slack.
    let source = Source::new(900_000, MAINNET_MAX_TIP_AGE.as_secs() - 60);
    let tip = FreshTip::new(source, Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
}

#[tokio::test]
async fn future_timestamp_counts_as_fresh() {
    let source = Source::new(900_000, 0);
    // A header two hours ahead of this clock (allowed by consensus).
    struct Ahead(Arc<Source>);
    #[async_trait]
    impl ChainProvider for Ahead {
        fn trust_level(&self) -> TrustLevel {
            self.0.trust_level()
        }
        async fn get_block_height(&self) -> Result<u64, ChainError> {
            self.0.get_block_height().await
        }
        async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
            let mut header = self.0.get_block_header(height).await?;
            header.timestamp += 2 * 3600;
            Ok(header)
        }
        async fn estimate_fee(&self, t: u32) -> Result<FeeEstimate, ChainError> {
            self.0.estimate_fee(t).await
        }
        async fn is_tx_confirmed(&self, txid: &str, n: u32) -> Result<bool, ChainError> {
            self.0.is_tx_confirmed(txid, n).await
        }
        async fn is_synced(&self) -> bool {
            true
        }
    }
    let tip = FreshTip::new(Arc::new(Ahead(source)), Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
}

#[tokio::test]
async fn height_zero_is_not_a_tip_even_without_a_bound() {
    let tip = FreshTip::new(Source::new(0, 0), None);
    let error = tip.get_block_height().await.unwrap_err();
    assert!(matches!(error, ChainError::NotAvailable(_)), "{error}");
}

#[tokio::test]
async fn regtest_accepts_any_age() {
    let tip = FreshTip::wrap(Source::new(150, 30 * 24 * 3600), Some("regtest"));
    assert_eq!(tip.get_block_height().await.unwrap(), 150);
}

#[tokio::test]
async fn wrap_applies_the_network_bound() {
    let old = 4 * 3600;
    assert!(FreshTip::wrap(Source::new(900_000, old), Some("bitcoin"))
        .get_block_height()
        .await
        .is_err());
    assert_eq!(
        FreshTip::wrap(Source::new(900_000, old), Some("signet"))
            .get_block_height()
            .await
            .unwrap(),
        900_000
    );
}

#[tokio::test]
async fn read_failure_is_an_error_not_a_height() {
    let source = Source::new(900_000, 60);
    source.fail.store(true, Ordering::SeqCst);
    let tip = FreshTip::new(source.clone(), Some(MAINNET_MAX_TIP_AGE));
    assert!(matches!(
        tip.get_block_height().await,
        Err(ChainError::Connection(_))
    ));
    // Failures are not cached: the source is asked again and recovers.
    source.fail.store(false, Ordering::SeqCst);
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
}

#[tokio::test]
async fn header_is_reused_briefly_and_judged_by_its_own_time() {
    let source = Source::new(900_000, 60);
    let tip = FreshTip::new(source.clone(), Some(MAINNET_MAX_TIP_AGE));
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
    source.height.store(900_001, Ordering::SeqCst);
    assert_eq!(tip.get_block_height().await.unwrap(), 900_000);
    assert_eq!(source.header_reads.load(Ordering::SeqCst), 1);
    // An expired entry is read again.
    {
        let mut cached = tip.cached.lock().await;
        if let Some((_, read_at)) = cached.as_mut() {
            *read_at = Instant::now() - TIP_CACHE_TTL;
        }
    }
    assert_eq!(tip.get_block_height().await.unwrap(), 900_001);
    assert_eq!(source.header_reads.load(Ordering::SeqCst), 2);
    // A cached header that has aged past the bound is refused, not reused.
    let mut cached = tip.cached.lock().await;
    if let Some((header, _)) = cached.as_mut() {
        header.timestamp = now() - MAINNET_MAX_TIP_AGE.as_secs() - 60;
    }
    drop(cached);
    assert!(tip.get_block_height().await.is_err());
}

#[tokio::test]
async fn other_reads_pass_through() {
    let source = Source::new(900_000, MAINNET_MAX_TIP_AGE.as_secs() * 2);
    let tip = FreshTip::new(source.clone(), Some(MAINNET_MAX_TIP_AGE));
    // The source's own sync state is unchanged by the tip bound.
    assert!(tip.is_synced().await);
    assert!(tip.is_synced_with_height(900_000).await);
    assert_eq!(tip.estimate_fee(6).await.unwrap().sat_per_vbyte, 3.0);
    assert!(tip.is_tx_confirmed("00", 1).await.unwrap());
    assert_eq!(tip.get_block_header(5).await.unwrap().height, 5);
    assert_eq!(tip.trust_level(), TrustLevel::FullValidation);
    assert_eq!(tip.max_age(), Some(MAINNET_MAX_TIP_AGE));
}
