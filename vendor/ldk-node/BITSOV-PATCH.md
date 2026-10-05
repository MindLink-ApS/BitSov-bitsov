# BitSov stateless quote extension

Source: crates.io ldk-node 0.7.0, upstream https://github.com/lightningdevkit/ldk-node/tree/v0.7.0. Crates.io archive SHA-256: `d830ef2d6b00f089fb6e3ac845370ebf0f35f9d11ce81b3a097c1580d2dce358` (the pre-patch root lockfile checksum). Original licenses retained. Only production sources are vendored; standalone upstream integration test/bench targets and their unused dev dependencies are removed from the packaged Cargo manifest.

Local delta: expose Bolt11Payment::receive_stateless, delegating to ChannelManager::create_bolt11_invoice with payment_hash=None (which calls create_inbound_payment), without the payment-store insert or invoice log in receive_inner. On PaymentClaimed, insert an unknown stateless BOLT11 receipt as Succeeded before publishing PaymentReceived. Existing invoice APIs retain their behavior. No payment record is inserted on quote issuance or PaymentClaimable. LDK channel safety/HTLC persistence is unchanged.

Tests: konsensus-lightning/tests/stateless_quotes.rs checks an unstarted disposable regtest instance, including complete before/after disk snapshots. The shared mock and real loopback Noise regressions check no unpaid rows and settlement-only records.

Additional receive safety: reject fee skimming for unknown stateless BOLT11 payments, and retain Succeeded receipts on duplicate rejection. The upstream duplicate rejection changed Succeeded to Failed, which could reopen the single-use guard.

Production event regression (unstarted, fixed-seed regtest object with synthetic settlement events, no funds/network):

    cargo test --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_stateless_tests

The vendor unit-test lock is separate; workspace dependencies remain pinned by the root Cargo.lock. The vendor manifest adds tempfile for these disposable storage tests. No upstream integration tests or real node daemons run.

## Fixed LSPS2 funding minimum

Before claiming a stored fixed-amount `Bolt11Jit` payment, `PaymentClaimable`
validates the aggregate net against the persisted gross minus the negotiated
maximum opening fee. An amount below that minimum, an excessive skim, or invalid
fixed-amount terms fails the whole payment backwards before the preimage is
released. Rejection preserves the original gross/fee terms for retries and
restart. Variable-amount JIT invoices retain their existing fee-only policy;
BitSov's pilot does not issue them.

The check runs after LDK has assembled MPP parts and before either automatic
claim or manual-claim notification. It never rejects an individual shard merely
because it is below the whole-payment minimum. Existing `Succeeded` duplicate
protection remains before this check because settled records contain net, not
the original gross.

    cargo test --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_jit_tests

The regression invokes the production handler and uses LDK's existing in-memory
test channel managers to deliver multipart HTLCs. No node is started, no socket
is bound, and no real wallet or funds are used.

## Observed wallet sync health

`chain/sync_health.rs` records process-local success/failure observations in two
wallet slots. The first failure time survives retries; success clears only the
corresponding slot, and the oldest outstanding failure is exposed as
`NodeStatus.chain_sync_failure`. Bitcoind's combined listener synchronization and
polling use one slot; Esplora/Electrum record onchain and Lightning wallet results
separately. Remote error strings, credentials, URLs and paths are not retained.

The existing sync results are recorded and returned unchanged. Channel manager,
chain monitor, sweeper, broadcast and persistence behavior is unchanged. The
BitSov adapter exposes this only as the owner `/status` `chain_sync` diagnostic;
it does not change `money_ready`, payment dispatch or wallet freshness semantics.

    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --locked --lib sync_health

The unit regression checks retry timestamps, independent wallet failures and
clearing on success. Workspace regressions cover owner-only status, unchanged
readiness/dispatch after failure, and failed Core synchronization with an isolated
process network guard permitting only the disposable RPC fixture.

## Serialized on-chain operations / local spend reservations (#189)

Baseline remains the crates.io **ldk-node 0.7.0** archive identified above
(SHA-256 `d830ef2d6b00f089fb6e3ac845370ebf0f35f9d11ce81b3a097c1580d2dce358`).
Every vendor delta in this branch is covered below:

- `wallet/local_spends.rs` (new): durable input ownership under the
  `bitsov_local_spends` KV namespace, keyed by txid. Version 2 adds creation and
  last-sighting Unix times; legacy rows migrate once. Malformed/unreadable rows
  are skipped, counted, and warned about by `Wallet::new`, with diagnostics
  exposed to the owner API. Confirmation/conflict removes reservations only
  after `ANTI_REORG_DELAY` confirmations, matching payment finality. Earlier
  confirmations release change but preserve durable input ownership through a
  shallow reorg, restart, and mempool eviction. Wallet-known confirmations
  (including conflicting spends) block owner/absence release below finality,
  even if the source reports not-found (such as Core without txindex). Successful
  chain-source absence after 24 hours since creation/last sighting or explicit owner abandonment
  after definitive source absence releases stranded inputs. Lookup errors do
  not count as absence. The adapter reconciles on startup and every minute, with
  a total 10-second pass budget and a rotating cursor to prevent starvation.
- `wallet/mod.rs`: shared operation gate, input/change exclusions in every
  ordinary transaction builder, reservation registration before a signed tx is
  handed to LDK or its broadcaster, BDK persistence, source visibility and
  confirmation reconciliation, abandonment and owner diagnostics. `Wallet::new`
  now returns `Result<Self, Error>` because loading/migrating the ledger can
  encounter a storage failure. Pre-broadcast persistence failures run the same
  abandonment helper, including KV cleanup when BDK persistence fails. This
  covers the funding-construction error branch before `event.rs` closes it.
  The upstream debug assertion that confirmed funds are always available for
  anchor spends was removed: reservations can legitimately exhaust those funds;
  selection returns insufficient funds instead of panicking.
- `error.rs`: adds a clear retained-reservation error when owner release would
  override the wallet's confirmation evidence below finality.
- `wallet/bump.rs` (new): local coin-selection wrapper reconstructs persisted
  bump claim ownership and delegates fee/weight selection to LDK's unchanged
  selector. Last-resort conflicts may involve other bumps, never ordinary
  payment/funding reservations. `types.rs` swaps the
  `BumpTransactionEventHandler` coin-selection source to this wrapper.
- `wallet/persist.rs`: makes the existing KV-store handle available to the
  sibling wallet modules; no storage backend is added.
- `builder.rs`: handles the fallible `Wallet::new` signature and constructs the
  local bump wrapper.
- `event.rs`: definitive funding rejection and `DiscardFunding` abandon the
  prepared spend; bump workers wait on the shared gate in runtime-tracked tasks
  so the funding event processor cannot deadlock. Funding construction errors
  already abandon before returning to this handler.
- `lib.rs`: exposes the shared operation gate, source-verification update,
  reservation metadata/unreadable-row diagnostics, source reconciliation, and
  specific abandonment. The embedding adapter authenticates owner releases
  and holds the gate across lookup and release; pairing tokens cannot release
  reservations. Owner release requires the same definitive source not-found as
  reconciliation. Visibility, lookup errors, missing source, and a 10-second
  lookup timeout refuse release with a clear error; there is no force flag.
- `wallet/money_tests.rs` (new) and its module registration: disposable,
  unstarted-node regressions for real BDK selection/signing/persistence,
  concurrency, restart, source absence, owner release, corrupt rows,
  persist-failure cleanup, shallow reorgs, and finality on both sync paths.
  `tests/bitsov_jit.rs` changes its wallet wrapper import to keep the existing JIT event regressions exercising production code.

Offline commands (deny networking at the OS level; exclude known socket fixtures
from the Lightning library suite):

    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_money_tests
    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_
    cargo test --offline --locked -p konsensus-lightning --lib
    cargo test --offline --locked -p konsensus-api --lib
    cargo test --offline --locked -p konsensus-api --test local_spend_tests
    cargo clippy --offline --locked -p konsensus-lightning -p konsensus-api --all-targets -- -D warnings

No recipient amount, fee calculation, admission policy, or settlement rule is
changed. Explicit abandonment and bounded absence cannot revoke an already
signed transaction: it may propagate later, and the release API says so.

## Closed-channel funding evidence

`Node::channel_funding_outpoint` exposes a monitor's funding outpoint even after
force-close. It is a local read, not proof of broadcast or confirmation. The
BitSov provider verifies removed-channel funding against the configured chain
source before counting the claim in either closing funds or its legacy total;
monitor persistence and recovery remain unchanged.

`LightningBalance::from_ldk_balance` selects the same on-close balance candidate
as LDK's `claimable_amount_satoshis`: the latest candidate when confirmed index
is zero, otherwise the confirmed candidate. Amount and transaction fee remain
paired. This keeps subtraction from the aggregate exact with pending splices.
The candidate remains an estimate, not proof of replacement funding confirmation.

    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --lib bitsov_funding_tests

## Chain-sync retry resilience (2026-10-03)

Investigation of test #5 (Atlas run 2 item 13, and the repeat around 04:14 on
3 October), against ldk-node 0.7.0, esplora-client 0.12.3 and
lightning-transaction-sync 0.2.1:

- Ordinary Esplora errors and the existing inner wallet timeouts already return
  through the sync-status cleanup and retry on later background ticks. The HTTP
  client already has a 10-second per-request deadline; this patch retains it.
- A cancelled outer Esplora sync leaves `WalletSyncStatus::InProgress` behind.
  Subsequent subscribers wait without a deadline, blocking the shared sequential
  wallet/fee loop. An offline regression reproduces the stranded waiter before
  the fix. A drop guard now notifies subscribers and releases ownership; both
  owner work and subscriber waits have the existing wallet deadline (onchain
  20 seconds, Lightning 10 seconds). Subscriber timeout does not steal ownership
  from a still-running sync. Losing the last subscriber during notification is
  normal, not an assertion failure.
- **The production trigger remains unconfirmed.** Normal request errors/timeouts
  do not cancel the outer owner. No incident `ldk_node.log`, task dump or live
  transport evidence was available under the no-network constraint. This is a
  demonstrated cancellation fix and resilience hardening, not proof that beta's
  hours-long incident is resolved. Restart also clears process-local sync health.
- LDK's detailed diagnostics use its default filesystem logger. Background
  failures additionally use the application's `log` facade. The node explicitly
  enables `tracing-subscriber`'s `tracing-log` feature; `logging::init()` calls
  `SubscriberInitExt::init()` once at startup, which installs `LogTracer` and sets
  the facade's maximum level. A `ldk_node::chain_sync=warn` output directive
  admits WARN/ERROR and suppresses INFO/DEBUG/TRACE for that target; other LDK
  targets retain their existing default/environment levels. The subprocess test
  exercises this same startup subscriber and captures the failure payload on
  stdout, including with `RUST_LOG=off`. Journald receives it when the service
  captures stdout; no live journal or beta incident was inspected.
  The earlier build already enabled the bridge through subscriber default
  features, so the claim that a missing bridge caused beta's absent journal
  line is not supported. The new explicit feature and test make the dependency
  and filtering contract visible. The line contains only fixed operation and
  error categories plus a numeric delay:
  `chain_sync_failed operation=onchain|lightning|fees kind=sync_failed|timeout retry_in_secs=N`.
  No remote error text, URLs, credentials, transaction IDs or wallet data enters
  this message. Existing detailed file logging is unchanged.

Esplora/Electrum background wallet and fee workers now wait independently and
retry after 10, 20, 40, 80, 160, then at most 300 seconds, indefinitely. Every
failed background attempt emits one fixed error line, bounded to one per worker
per 10 seconds. Success restores the configured interval, measured from completion;
missed ticks never cause a catch-up burst. Fees retain their delayed first tick.
Shutdown interrupts retry sleep and lets an active attempt finish under its source
limits. These workers isolate asynchronous waits, not blocking persistence, mutex
operations or arbitrary panics. Bitcoin Core polling is unchanged.

Electrum intentionally retains its existing owner cleanup on normal return.
Its wallet calls use `spawn_blocking`, and the Lightning worker holds confirmables
and can still apply chain updates after its join handle is dropped. Copying the
Esplora cancellation guard would release ownership while that worker can still
run, allowing a second caller to overlap it. A safe Electrum cancellation fix
needs worker lifetime/draining ownership, not just a drop guard around the async
wait. Existing Electrum timeouts can also detach blocking work; this patch does
not claim to solve that. Shutdown abort during an attempt can still strand its
async sync status, so restarting the process remains necessary in that case.

`money_ready`, sync-health slots, successful-sync timestamp updates, settlement,
channel safety and custody semantics are unchanged. Failure never fabricates a
successful sync or resets another wallet's failure. The Esplora HTTP builder is
extracted to permit injection of a never-resolving DNS implementation in the
request-timeout test. Names are explicitly ASCII-lowercased; invalid names or
values now return `BuildError::InvalidEsploraHeaders` through `Builder::build()`.
HTTP client construction failures return `BuildError::EsploraClientSetupFailed`.
Neither error includes header contents. Mixed-case names (including
`Authorization`) were already accepted by the locked `http` crate's normalizing
`HeaderName::from_bytes`; the actual regression was panicking on invalid input.
Tests cover mixed-case standard/custom names and invalid names/values. Valid
custom headers, the 10-second request deadline and default retry behavior are
preserved.

Offline verification for the fix round (2026-10-03): all Cargo commands used
`--offline --locked` and ran inside macOS `sandbox-exec` with
`(version 1)(allow default)(deny network*)`, including subprocess tests. No
network connections, including `127.0.0.1:3141`, were permitted.

    cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib
    cargo test --offline --locked -p konsensus-lightning --lib
    cargo test --offline --locked -p konsensus-node --lib
    cargo test --offline --locked -p konsensus-node --bin konsensus
    cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib --tests
    cargo clippy --offline --locked -p konsensus-node -p konsensus-lightning --all-targets -- -D warnings

The full vendor library suite passes: **41 tests**. It includes settlement,
cancellation, source-error recovery, timeout, log, bounded-backoff,
worker-isolation, shutdown and header-construction regressions. Virtual time
drives retry tests; the HTTP timeout test never resolves an address.

The unrestricted test selections above were also attempted under network denial.
They are **not all green**: 77 Lightning tests (46 LNbits and 31 LND), 5 node
library STUN tests, and 79 node binary tests (message/peer/session/remote-access
and STUN) fail with socket permission errors. Every failure was inspected for
`PermissionDenied` / `Operation not permitted`; networking was not enabled.
Re-running with only those exact failing test names excluded via `--skip` passes
**148 Lightning**, **65 node library**, and **579 node binary** tests (one
pre-existing ignored binary test). No source tests were removed, ignored or
weakened. The binary passes include the subprocess log-capture regression for
default filters, global OFF, unrelated LDK DEBUG, and exact chain-sync OFF/TRACE
overrides. Before the fix, that regression caught unwanted chain-sync INFO, and
the invalid-header regressions reproduced both panics.

Node and Lightning Clippy pass with warnings denied. Vendor Clippy completes
with **281 pre-existing warnings**, unchanged from the prior retry commit; its
strict `-D warnings` run is not clean. These offline results do not verify a live
journal, network behavior or resolution of the production incident.

Doctrine: 1, 2, 5 and 6 hold: settlement/admission and custody remain unchanged;
Bitcoin remains chain evidence, never identity; diagnostics disclose no identifiers;
incident-resolution claims remain explicitly unverified. Lines 3 and 4 unchanged.

## Shared Esplora rate limiting and rebroadcast eligibility (2026-10-03)

Incident evidence: `TEST5-SANITY-LOG.md`, Atlas run 4 step 1, and the supplied
redacted `beta-ldk-sync-0403.txt`. The 1,385-line excerpt contains 252 broadcast
failures, 254 Lightning wallet sync timeouts, 96 on-chain failures, and 350 lines
mentioning 429. Broadcast errors recur about every 30 seconds. The excerpt does
**not** identify the transaction: the ghost commitment is a plausible driver,
not proven incident attribution. No live backend or node was contacted.

Production changes:

- `chain/rate_limit.rs`: one process-local Esplora HTTP admission state shared by
  the on-chain wallet, Lightning sync, fees, funding/visibility verification, and
  broadcasts, including their cloned clients and internal GET retries. A 429
  establishes a cooldown of 10, 20, 40, 80, 160, then at most 300 seconds without
  a usable Retry-After. Numeric and HTTP-date Retry-After are clamped to 300
  seconds; malformed headers fall back to exponential delay. GET calls during
  cooldown return a fixed rate-limit error without HTTP, with one GET recovery
  probe admitted. Each broadcast POST has its own bounded wait and bypasses GET
  admission after that wait, even if another request has extended the cooldown.
  A non-429 recovery probe clears the episode; a POST admitted during a newer
  cooldown does not clear that newer episode. Cancelled or failed probes release
  ownership with a short cooldown. Older concurrent
  responses cannot clear a newer 429. Huge numeric Retry-After cannot overflow
  an Instant. Journal output names only the parsed backend hostname, fixed kind,
  and numeric delay; response text, credentials, paths and query strings are
  excluded.
- `chain/esplora.rs`: installs that transport, classifies wallet/fee failures,
  queries funding with `get_tx_info` (`GET /tx/{txid}`), and retains a broadcast
  across 429 cooldowns. The existing request and wallet attempt deadlines remain;
  each POST waits at most one 300-second cooldown outside its HTTP attempt
  deadline, then attempts the POST as its own probe. A newer cooldown cannot
  extend that wait. Shutdown can cancel the wait. Actual HTTP response fixtures
  exercise fee, on-chain wallet, Lightning wallet, funding, and POST paths without
  sockets.
- `tx_broadcaster.rs`: repeated transactions back off 30, 60, 120, 240, then at
  most 300 seconds, across all supported chain sources. New transactions are
  immediately eligible. A package with a new/due child retains its parents for
  relay. Identical pending packages are coalesced so recovery cannot flush a
  backlog of duplicates. Idle history expires after 24 hours. Queue-full refusal
  does not advance a transaction's retry clock. Every in-flight package is retained
  before the first await and resumed if the same Node's worker is aborted and
  restarted; completing one package clears only its own pending ownership. This is
  process-local scheduling, not a new durable transaction store.
- `chain/broadcast.rs`, `chain/mod.rs`, `lib.rs`: before dispatch, inspect only
  spends of monitored **closed** channels' exact funding outpoints. Explicit
  `GET /tx/{txid}` 404 proves absence; a valid transaction response (confirmed
  or mempool) proves presence. `/tx/{txid}/status` is not presence evidence:
  incident backends return 200 `{"confirmed":false}` even for unknown txids.
  Core/Electrum use the adapter's existing #192 indexed/synced proof via a verifier
  callback. Missing verifier, malformed data, timeouts, 429, and
  every other error remain inconclusive. Suppress the absent-funding commitment
  and its descendants, retaining ordinary/open-channel transactions and packages
  supplying their own funding parent. One ten-second verification budget preserves
  earlier definitive results when a later lookup times out. Recheck on a later
  eligible broadcast: late funding propagation restores eligibility. A lagging
  Esplora index can report 404 temporarily; suppression is rechecked, never durable.
  Packages run independently under a cancellation-owned JoinSet: a parked package
  cannot hold later justice, HTLC-timeout/success, sweep or anchor packages behind
  its retries. Order within each package is preserved. No monitor,
  wallet reservation, channel, or settlement record is deleted or marked settled.
- No configured chain source: the builder's implicit upstream Esplora default
  cannot supply funding evidence. An error verifier is installed before the
  source is shared, so release, reconciliation, #192 balances, and ghost
  suppression all refuse to infer absence without issuing a request. Explicit
  Esplora clients validate their base URL before the `/tx/{txid}` transport runs.
  In-memory 404 transports count calls and prove that both missing-source paths
  make zero requests, independently of network availability. Only a configured
  endpoint's explicit 404 remains absence evidence.
- `chain/sync_health.rs`, `error.rs`, `chain/sync_retry.rs`: retain the oldest
  outstanding failure timestamp and expose rate-limited failure kind, including
  a 429 first observed by broadcast/fees. A successful other wallet cannot hide
  an outstanding wallet's rate-limit failure. The adapter maps it to owner status
  `chain_sync.last_error_kind = "rate_limited"`; other failures remain
  `"sync_failed"`. #196's background retry schedule, cancellation-safe wallet
  ownership, subscriber deadlines, and fee-barrier startup retries are retained.
  Startup's retry classification includes the new rate-limit error.
- The adapter's closed-funding queries and Esplora reservation reconciliation,
  send verification and owner release use this same Node transport. Core/Electrum
  transaction visibility semantics are unchanged. The existing bounded startup
  endpoint-selection probes run before Node construction; they are not continuous
  runtime failover. No new backend, directory, account or service endpoint is added.

The small Esplora-client transport hook is documented separately in
`../esplora-client/BITSOV-PATCH.md`; its baseline checksum remains the previously
locked 0.12.3 archive. Locks retain all unrelated dependency versions. `httpdate`
1.0.3 was already present in the workspace lock and is used to parse HTTP dates;
`http` is a vendor test-only dependency for socket-free responses.

Verification and the exact network-dependent fixture exclusions are recorded in
`../../docs/testing/rate-limit-rebroadcast-offline.md`. Existing HTTP-evidence
unit coverage moved from the adapter's private decoder to the actual shared
vendor-client fixture; adapter tests still check both aggregate balance views.
`money_ready`, paid admission, fee calculation and custody semantics are unchanged.

Doctrine: 1 and 5 hold (settlement and self-custody preserved); 2 holds (Bitcoin
remains chain/admission infrastructure); 3 and 4 unchanged; 6 holds (explicit
rate-limit diagnostics and no claim of live incident resolution).

## Owner-selected channel funding policy (#190)

Baseline/version/checksum remain the 0.7.0 archive above. Added `funding.rs`:
closed economy/normal/fast choices reuse existing unadjusted estimator targets
(144/12/6 blocks), with an opaque estimator-selected policy and optional absolute
fee cap. `fee_estimator.rs` tracks cache update age and refuses missing/stale
(older than twice the configured fee refresh interval, minimum 900 seconds)
estimates for this API. Legacy opens retain the original cached/fallback path. The three chain adapters track which targets have real, finite, positive source estimates; synthetic fallback rates remain available to LDK but cannot qualify as funding quotes. `lib.rs` exposes quote/open/failure methods;
policy is persisted before `create_channel`, keyed by a marked user-channel ID.
Missing/corrupt records for marked IDs fail closed, including after restart.
Policies/failures remain as small durable diagnostic records; automatic pruning
is deliberately absent so replay cannot lose an enforceable policy.

`event.rs` uses the policy-aware wallet builder and records construction failure
before closing an unfunded channel. The first recorded refusal is terminal at the wallet builder, survives restart, and cannot be replaced by a later retry reason (the pinned LDK does not persist FundingGenerationReady itself across restart). `wallet/mod.rs` checks the complete unsigned
PSBT fee before signing or reservation, and `error.rs` names cap refusal. Legacy
unmarked channels retain their existing estimator behavior. No upstream
confirmation/commitment/HTLC logic was changed, no new fee estimator requests
were added, and no CPFP operation or automatic funding fee escalation was added.
See `docs/ops/funding-fees.md` for owner API behavior and the precise CPFP gap.

Validation (disposable wallet; no socket/node start):

```sh
cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib funding
cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib bitsov_money_tests
cargo test --offline --locked -p konsensus-api --test funding_fee_tests
```

## Opt-in private-channel forwarding (#225, 2026-10-05)

`Config::accept_forwards_to_priv_channels` defaults to false. When explicitly
true, `default_user_config` enables only the matching LDK flag, after the
`may_announce_channel` guard. With no node alias, `announce_for_forwarding`
stays false and `force_announced_channel_preference` stays true. Existing
announcement eligibility and LSPS2/async-server overrides are unchanged.
BitSov exposes this as `[lightning] forward_to_private_channels = true` and
passes it through `LdkConfig`; no alias is set.

The vendor policy unit test covers both flag values with and without listening
addresses. The `regtest-e2e` scenario
`private_forwarding::production_hub_private_forwarding_is_opt_in` builds the
hub through production `LdkProvider::new`, with no LSPS2 service: disabled
forwarding must produce `PrivateChannelForward` after dispatch; enabled
forwarding must settle A→hub→B over unannounced channels at the exact hop fee.
The scenario is compiled locally; execution requires the CI regtest daemons.

Forwarding exposure on a hub that opts in: peers can route payments through it, so
its channel balances shift (outbound on one side, inbound on the other) and may need
rebalancing; it can be probed, which reveals coarse capacity on its private channels to
the payer; forwarded HTLCs lock liquidity until they settle or time out (bounded by
LDK's CLTV limits and max-HTLC-in-flight settings); it earns LDK's default forwarding
fee (base 1000 msat, 0 ppm, unless configured otherwise). Forwarding signs the usual
new commitment transactions on both channels, but it gives the hub no new signing role
or custody, and it never sends its own funds without a matching incoming HTLC. Disk
admission does not gate forwarded HTLCs: monitor updates are still written; the only event
ldk-node raises for a forward (PaymentForwarded) arrives after settlement, and the gate
hooks only PaymentClaimable and OpenChannelRequest, so it never gates a forward.

Doctrine: 1 holds (every routed act is still a payment that settles end to end); 2
holds (no node or channel announcement; Bitcoin stays settlement infrastructure); 3 and
4 unchanged (no new server role; the hub is an ordinary peer the users already pay); 5
holds (self-custody unchanged; the hub never takes custody of forwarded value); 6 holds
(the exposure above is documented and default-off).

## Bounded owner-policy LSPS2 opens (2026-10-05)

`liquidity/jit.rs` replaces the three pre-open failure drops with a durable
`bitsov_lsps2` journal (`lsps2_open.rs`), five attempts and a 60-second deadline.
Buy assigns a distinct BSJI policy-bearing user ID; `funding.rs` fails closed
for missing/corrupt policies under this marker, just as for #190's BSFP IDs.
The wallet reuses #190's fresh estimator and pre-signing complete-fee cap.

Reservations include full channel capacity, anchor allowance and funding fee
ceiling. A persisted dispatch fence prevents duplicate opens after uncertainty.
Lifecycle events persist observations before acknowledgment. Ready channels
release a concurrent slot; closed channels retain capital through monitor
archival and sweep completion. Unknown pre-patch closed exposure blocks new
opens conservatively. Lowered owner caps stop waiting work after restart.

No upstream HTLC/admission or fee-authority rules change. Exhaustion calls
upstream `channel_open_failed` then `channel_open_abandoned`, only after definite
pre-dispatch failure. Pending retries retain their intercepted payments. The
4,096-record journal retains tombstones and fails closed on corruption/write
failure. The upstream event-delivery crash window is unchanged: durability
starts at the vendor handler, not at liquidity-manager enqueue.

`Node::lsps2_service_metrics` exposes durable counters and conservative gauges;
BitSov publishes these through its existing Prometheus recorder. Settled skim
accumulates across MPP forwards, bounded by the quote; LDK has no HTLC ID for
exact replay deduplication, so this is at-least-once telemetry, not a ledger.
See `docs/LSPS2-LIQUIDITY.md` for settings, units and conservative limitations.

Tests: vendor `bitsov_jit`, `funding`, `bitsov_money_tests`; application LSPS2
configuration/tariff tests; real `hub_jit_then_stateless_admission` regtest with
insufficient hub funds, retry recovery, fee-cap and restart telemetry checks.
