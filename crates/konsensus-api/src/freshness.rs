//! Data freshness headers (G-STALENESS-MARKER).
//!
//! Six pinned read routes — `GET /api/v1/payments/balance`,
//! `/payments/channels`, `/health`, `/messages`, `/pricing` and `/peers` — attach:
//!
//! - `BitSov-Data-As-Of: 2026-09-27T08:20:00Z` — RFC 3339, UTC (`Z`), whole
//!   seconds, truncated. The oldest "last known current" time among the
//!   sources the handler used. Clamped to the node clock, so never in the
//!   future. Absent when the node has no time for the data.
//! - `BitSov-Data-Stale: 1` — the node's own judgement that the data is past
//!   its freshness bound. Absent means "not known stale", not "fresh".
//!
//! Only successful (2xx) responses carry them: a handler that returns an
//! [`ApiError`](crate::error::ApiError) never builds a [`DataFreshness`].
//! Purely additive: no body, status, route or auth change.
//!
//! The headers are not listed in `Access-Control-Expose-Headers`: the
//! consumer (bitsov-app's host-side broker) reads these routes over loopback
//! from Rust, not from the webview, so CORS does not apply to it.
//!
//! See `docs/v2/API_DATA_FRESHNESS.md` for the per-route sources.

use std::time::{Duration, SystemTime};

use axum::http::{HeaderName, HeaderValue};
use axum::response::{IntoResponseParts, ResponseParts};
use chrono::{DateTime, SecondsFormat, Utc};

use konsensus_core::traits::lightning::WalletSync;

/// `BitSov-Data-As-Of` (header names are case-insensitive on the wire).
pub const DATA_AS_OF: HeaderName = HeaderName::from_static("bitsov-data-as-of");

/// `BitSov-Data-Stale`.
pub const DATA_STALE: HeaderName = HeaderName::from_static("bitsov-data-stale");

/// A locally synced wallet (LDK) whose last sync is at least this old is
/// marked stale. LDK syncs every 30 s (Lightning) / 80 s (on-chain) by
/// default, so this is several missed syncs, not one slow one.
pub const WALLET_SYNC_STALE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Freshness of the data in one response; becomes the two headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataFreshness {
    as_of: Option<SystemTime>,
    stale: bool,
}

impl DataFreshness {
    /// Data read from its source at `at` (take the time *before* the read).
    pub fn at(at: SystemTime) -> Self {
        Self {
            as_of: Some(at),
            stale: false,
        }
    }

    /// Data read from its source now. Call before the read, not after, so the
    /// stamp never claims the data is newer than it is.
    pub fn now() -> Self {
        Self::at(SystemTime::now())
    }

    /// No time is known for the data: neither header is sent.
    pub fn unknown() -> Self {
        Self {
            as_of: None,
            stale: false,
        }
    }

    /// Mark the data as past its freshness bound.
    pub fn stale(self) -> Self {
        Self {
            stale: true,
            ..self
        }
    }

    /// Wallet figures (`/payments/balance`, `/payments/channels`).
    ///
    /// `read_at` is the time taken just before the provider was asked, used
    /// for [`WalletSync::Live`] backends.
    pub fn from_wallet_sync(sync: WalletSync, read_at: SystemTime) -> Self {
        match sync {
            WalletSync::Live => Self::at(read_at),
            WalletSync::SyncedAt(secs) => {
                let synced = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
                let this = Self::at(synced);
                match read_at.duration_since(synced) {
                    Ok(age) if age >= WALLET_SYNC_STALE_AFTER => this.stale(),
                    _ => this,
                }
            }
            WalletSync::NeverSynced => Self::unknown().stale(),
        }
    }

    fn as_of_header(&self, now: SystemTime) -> Option<HeaderValue> {
        let at: DateTime<Utc> = self.as_of?.min(now).into();
        let text = at.to_rfc3339_opts(SecondsFormat::Secs, true);
        HeaderValue::from_str(&text).ok()
    }
}

impl IntoResponseParts for DataFreshness {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        if let Some(value) = self.as_of_header(SystemTime::now()) {
            res.headers_mut().insert(DATA_AS_OF, value);
        }
        if self.stale {
            res.headers_mut()
                .insert(DATA_STALE, HeaderValue::from_static("1"));
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn as_of_is_rfc3339_utc_whole_seconds_truncated() {
        let at = t(1_790_497_200) + Duration::from_millis(999);
        let v = DataFreshness::at(at)
            .as_of_header(t(1_790_497_300))
            .unwrap();
        assert_eq!(v, "2026-09-27T08:20:00Z");
    }

    #[test]
    fn as_of_ahead_of_node_clock_is_clamped_to_now() {
        let v = DataFreshness::at(t(2_000)).as_of_header(t(1_000)).unwrap();
        assert_eq!(v, "1970-01-01T00:16:40Z");
    }

    #[test]
    fn unknown_sends_no_as_of() {
        assert!(DataFreshness::unknown().as_of_header(t(1_000)).is_none());
    }

    #[test]
    fn live_wallet_is_as_of_the_read_and_not_stale() {
        let f = DataFreshness::from_wallet_sync(WalletSync::Live, t(5_000));
        assert_eq!(f, DataFreshness::at(t(5_000)));
    }

    #[test]
    fn wallet_sync_just_inside_the_bound_is_not_stale() {
        let bound = WALLET_SYNC_STALE_AFTER.as_secs();
        let f =
            DataFreshness::from_wallet_sync(WalletSync::SyncedAt(10_000), t(10_000 + bound - 1));
        assert_eq!(f, DataFreshness::at(t(10_000)));
    }

    #[test]
    fn wallet_sync_at_the_bound_is_stale() {
        let bound = WALLET_SYNC_STALE_AFTER.as_secs();
        let f = DataFreshness::from_wallet_sync(WalletSync::SyncedAt(10_000), t(10_000 + bound));
        assert_eq!(f, DataFreshness::at(t(10_000)).stale());
    }

    #[test]
    fn wallet_sync_ahead_of_clock_is_not_stale() {
        let f = DataFreshness::from_wallet_sync(WalletSync::SyncedAt(20_000), t(10_000));
        assert_eq!(f, DataFreshness::at(t(20_000)));
    }

    #[test]
    fn never_synced_wallet_is_stale_with_no_time() {
        let f = DataFreshness::from_wallet_sync(WalletSync::NeverSynced, t(10_000));
        assert_eq!(f, DataFreshness::unknown().stale());
    }
}
