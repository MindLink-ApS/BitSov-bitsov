//! Shared with the chain/pricing client, including endpoint cooldown state.
pub(super) use esplora_client::rate_limit::RateLimitedTransport;

#[cfg(test)]
mod bitsov_rate_limit_tests {
    use super::*;
    use std::time::Duration;
    fn response(status: u16, retry: Option<&str>) -> Result<reqwest::Response, esplora_client::Error> {
        let mut builder = http::Response::builder().status(status);
        if let Some(retry) = retry { builder = builder.header("retry-after", retry); }
        Ok(builder.body(String::new()).unwrap().into())
    }
    #[tokio::test(start_paused = true)]
    async fn retry_after_blocks_other_operations_and_recovers() {
        super::super::sync_retry::bitsov_retry_tests::capture_logs();
        let transport =
            RateLimitedTransport::new("https://user:secret@chain.invalid/private?token=secret");
        assert!(transport
            .run(false, || async { response(429, Some("120")) })
            .await
            .is_err());
        assert!(transport
            .run(false, || async { panic!("sync/fee/broadcast must share cooldown") })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(119)).await;
        assert!(transport
            .run(false, || async { panic!("Retry-After must be respected") })
            .await
            .is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(transport
            .run(false, || async { response(200, None) })
            .await
            .is_ok());
        let logs = super::super::sync_retry::bitsov_retry_tests::captured_logs();
        assert!(logs.iter().any(|line| line.contains(
            "chain_rate_limited kind=rate_limited backend_host=chain.invalid retry_in_secs=120"
        )));
        assert!(logs
            .iter()
            .all(|line| !line.contains("secret") && !line.contains("/private")));
    }
}
