# LDK startup retry (BOOT-FIX stage 1)

A healthy endpoint preflight does not guarantee that LDK's separate startup
fee request will succeed. BitSov now retries that actual request on LDK's
`FeerateEstimationUpdateFailed` and `FeerateEstimationUpdateTimeout` errors.
These errors occur before background tasks start in the pinned Esplora backend.
Other build/start errors are returned immediately, without retry.

- At most five real startup attempts, each subject to LDK's five-second fee
  timeout. Backoff is 2, 4, 8, then 8 seconds, with ±20% jitter.
- The 60-second connectivity budget includes preflight (up to two four-second
  probes). Another attempt is only admitted if its five-second window fits.
  Local build/storage operations are synchronous and are not network-timeout
  bounded.
- If the actual primary fee request fails, the next attempt uses the configured
  fallback. The primary is not re-probed. Switching drops the old unstarted node
  before rebuilding with the same entropy and storage directory; later attempts
  reuse that instance. Without a fallback, retries reuse the primary instance.
- No provider or ready API is exposed until startup succeeds. The event drainer
  and SCB timer are created only after success. Dropping startup during backoff
  cancels further attempts. An in-flight synchronous fee request completes or
  times out before cancellation is observed at the next yield; no detached
  startup worker survives cancellation. SIGINT and SIGTERM are handled during
  construction as well as during normal operation.

`BOOT_CHAIN_SOURCE_RETRY` logs show attempts while startup remains unready.
Exhaustion returns `BOOT_CHAIN_SOURCE_UNAVAILABLE`, with network, service host,
attempt count, elapsed milliseconds, and the last LDK fee error. The message
instructs the user to check connectivity and retry using their saved identity.
An unreachable service, invalid response, or unavailable usable fee data all
fail closed in this category. Invalid local network, mnemonic, endpoint URL,
listening address, or liquidity settings instead return `BOOT_INVALID_CONFIG`.
Storage and other startup errors retain their backend error and are not retried.
New structured diagnostics use the service host, not credentials, URL paths,
or response bodies.

Generated endpoint defaults and LDK's mainnet fee validation are unchanged.
No fee estimate is fabricated to bypass startup. Offline-tolerant onboarding
and availability of a local identity/status API while Lightning is offline are
**stage 2 and out of scope**. This genome change also requires a later release
and desktop sidecar pin update to reach apps using older binaries.

`crates/konsensus-lightning/tests/startup_retry.rs` exercises the real LDK
startup against loopback fixtures and disposable empty wallets: a healthy
preflight followed by HTTP failure or a five-second fee timeout, actual fallback,
persistent failure, empty mainnet fee data, invalid local config, cancellation,
readiness, single startup completion, and identity reuse.
