# Three-node paid flow: Atlas TEST5 regression

Doctrine: **1–6 hold.** Delivered content has a settled, recipient-bound payment
per act; tested refusals leave balances and spend budgets unchanged. Node/device
keys identify the participants, contacts stay in local stores, and the disposable
wallets are self-custodied. This is a local regtest test, not evidence of public
network privacy, production scale, or app UI correctness.

## Run locally or in CI

```sh
CARGO_TARGET_DIR=/tmp/bitsov-three-node-target \
BITCOIND_EXE=/path/to/bitcoind ELECTRS_EXE=/path/to/electrs \
  scripts/regress/three_node_paid_e2e.sh
```

Use the same offline Bitcoin Core and **Esplora-compatible** electrs fixtures as
[the existing regtest suite](regtest-e2e.md). Ordinary electrs without HTTP is
insufficient. Omit the executable variables to search PATH and the existing
`/tmp/bitsov-target-*` fixture caches. No download features are enabled. Requires
Unix (the real owner control socket), Python 3, cached Cargo dependencies, and
permission to bind loopback sockets. The test is feature-gated by `regtest-e2e`
and ignored in ordinary `cargo test` runs.

The entry point selects the ignored tests under `regtest_e2e::three_node::`,
offline and locked, with one test thread and one supervised process group. The
ghost scenario is excluded unless its dependency gate is enabled. It inherits the existing process-group supervisor: cancellation, panic,
failure and timeout clean up Core/electrs and temporary data. Default total
timeout is 1,800 seconds including compilation; override
`REGTEST_TIMEOUT_SECONDS`. `RUST_LOG=konsensus=debug,konsensus_api=debug` adds
protocol detail.

If either fixture is unavailable, the entry point **still compiles the enabled
test binary**, then prints `SKIP three-node paid E2E` and exits **77**. Compilation
failure retains its failure code. Ordinary Cargo runs report the Rust scenarios
as ignored with a reason; explicitly selecting the paid scenario without fixtures
panics instead of returning `ok`. Fixture startup and assertion failures never skip.

[The opt-in workflow](../.github/workflows/three-node-paid-e2e.yml) runs on
`workflow_dispatch` and nightly at 02:23 UTC, never on PRs or pushes. It downloads
Bitcoin Core **28.2** and Esplora electrs commit
**a33e97e1a1fc63fa9c20a116bb92579bbf43b254**, verifies exact archive SHA-256s
embedded in the workflow before extraction/use, caches Cargo dependencies, then
runs the offline runner. The hash provenance is the pinned `corepc-node 0.10.1`
and `electrsd 0.36.1` checksum manifests. Exit 77 is reported as **SKIPPED** in
the job summary and fails the job; exit zero also requires the runtime PASS marker.

PR #200 is merged. The ghost/unfunded-channel scenario still requires explicit
selection through the existing `REGTEST_GHOST_AFTER_PR200=1` runner gate (or the
workflow's `ghost_after_pr200` input). Enable it when verifying this fix:

```sh
REGTEST_GHOST_AFTER_PR200=1 scripts/regress/three_node_paid_e2e.sh
```

Both scenarios must run and pass when selected; no failure is swallowed. The
ordinary Cargo test run leaves the real Core/electrs scenarios ignored.

```sh
# Build and run the touched crate's ordinary tests, including fixture tests:
cargo test --offline --locked -p konsensus-node --features regtest-e2e
cargo clippy --offline --locked -p konsensus-node --all-targets \
  --features regtest-e2e -- -D warnings
python3 scripts/regress/test_regtest_e2e_runner.py -v
```

## Topology and coverage

```text
paired device -- production remote API router --> A
owner CLI    -- real Unix control.sock --------> A

                    A (app + LDK)
                   /             \
            private A–B       private A–C
                 /                 \
          B (app + LDK)        C (app + LDK)
                 |
         local HTTP fault proxies on A and B
                 |
       regtest electrs + Bitcoin Core
```

All three nodes run the production Noise transport, session/message handlers,
Axum routes, real LDK, and SQLite stores. They derive their mesh and Lightning
identities from their respective disposable mnemonics. A opens two direct
1,000,000-sat private channels through the owner API, confirming each before
opening the next. B and C initially have no outbound liquidity. Peer transport,
LDK and chain endpoints use ephemeral loopback ports. Bitcoin Core has network
activity, discovery, DNS seeds and P2P listening disabled. No public backend,
seed, RGS or external LSP is configured, and nothing targets port 3141.

HTTP client requests are in-process requests against `build_remote_router`, as
in the existing harness, with loopback connection metadata. The initial pairing
uses real device-key proof; subsequent token refreshes use remote challenge/token
routes. Owner approval crosses the real Unix socket. This guards remote route
mounting/auth behavior, but does **not** exercise the desktop app's Noise tunnel,
loopback proxy connection limits, or onboarding screens. B's restart stops and
reconstructs its handlers, transport, pairing service, SQLite/session manager and
LDK from disk inside the test process; it is not an OS crash/power-loss test.

Every scenario assertion/helper carries an incident label from
`pm/projects/bitsov/TEST5-SANITY-LOG.md` (Atlas runs 1–4):

| Incident | Regression assertion |
| --- | --- |
| Run 2 #7, #10–12: channel authority/funding blockers | Read+receive cannot open channels; owner opens A–B and A–C; both ends become usable. The existing explicit-fee refusal test remains intact. |
| Runs 1–2: quote unavailable; run 2 #15 / run 3 #2: remote elevation 404 and headless approval 500 | Read+receive can quote but compose returns 403 with no payment/invoice/delivery; remote request creates no authority by itself; no-terminal delivery writes mode-0600 owner approval; owner grants via control.sock; device refresh obtains spend; consumed approval file disappears. |
| Runs 1–2: paid send/receipt never reached | A pays admission plus the first message (4,002 msat), B decrypts, both hold E2EE sessions, receipt reports `fee_paid_msat: 0` (known direct-channel fee, not null). No content is sent before settlement. |
| Run 2 #17: A can receive zero sats | B's first attempted reply is `400 not_dispatched`, with no settled outgoing payment, balance change or budget debit. The few sats from first contact do not clear B's channel reserve. A then pays B a 50,000-sat regtest invoice: B gets outbound liquidity and A gets inbound liquidity. B's next reply settles for 2,001 msat and A decrypts it. Private local contact listing permits invoice/session control frames; each message still pays. |
| Run 4 steps 1,3: 429 and 30-second silence | B's application chain provider **and** real LDK use the HTTP fault proxy. While it returns 429, wallet readiness expires and sync reports stalled. A receives `503 peer_not_ready`, `retry_allowed: true` within 8 seconds, with no invoice records/payment. The peer wire refusal is `konsensus:not_ready:…`; the API preserves recipient context with `peer_not_ready`. Restoring HTTP success must clear sync failure, restore readiness and catch B up to a newly mined block within 360 seconds (above the 300-second backoff ceiling), without restarting B or manually syncing its wallets. |
| Run 4 step 6: stale sender price table | B sends a height-0 table with price 999,999 after a valid offer. A's real `/pricing/peers` response must retain the valid cached price; a first-contact quote must return the target's fresh 2,001 price within 8 seconds with no payment or payable invoice. A subsequent real wire update must appear fresh on the same endpoint. The endpoint reports freshness; it does not itself fetch a replacement table. The recipient backend failure path is the typed `peer_not_ready` scenario above, not a compose-price assertion. |
| Sender-side 429 | A's chain/LDK backend is limited. Compose must return local `503 not_ready` within 8 seconds without budget, capacity or invoice changes; background recovery must permit another 2,001-msat paid message. |
| Slow owner approval | C's first-contact quote ages beyond its signed absolute TTL before the owner approves through the real socket. Sending must replace the expired quote and deliver, with exactly two settled payments (one admission and one message) and a 4,002-msat debit. This proves no duplicate paid admission, not an exact count of unpaid wire requests. |
| Grant without recipient entries, reconnect | A's original grant has an empty recipient map; both first-contact approvals omit a contact budget. After C reconnects, compose must return `409 budget_exceeded`, reason `first_contact`, without any payment, invoice or budget change. The owner revokes that grant and issues explicit B/C recipient entries via the socket. Re-admission then costs exactly 4,002; a further reconnect pays the same amount without another owner confirmation. |
| Ghost channel (explicit runner gate) | Drop actual funding broadcasts before they reach Core, retain the real LDK monitor, force-close the unfunded channel, prove real `/tx/{txid}` returns 404, observe the provider querying that existence endpoint, and assert `closing_sats == 0` and aggregate exclusion despite a nonzero raw monitor claim. After initial close processing, observe 95 seconds with fresh 404 lookups and require zero additional commitment POSTs. Under 429, require a commitment POST, then observe 95 seconds: at most ten attempts, separated by at least the 10-second cooldown floor (1-second timestamp tolerance). Require a retained retry within the 300-second cooldown cap plus scheduling allowance. Unknown funding must remain recoverable. |
| Run 4 steps 2–3: recipient restart during active client flow | B closes/reopens its existing wallet and stores; mesh key, LN key, channel IDs and encrypted session survive. A keeps its client/grant, reconnects, and pays exactly 4,002 msat for one re-admission and one delivered message. B does not whitelist A, so reconnect cannot bypass the admission gate. |
| Run 2 #14–18: room flow blocked | A fans out a room message to B+C; two settled member receipts, 4,002-msat budget debit, known zero routing fee, two decrypted recipient-bound envelopes. |

The original routed positive-fee, no-route, call, meeting and room tests are
unchanged; use `scripts/regress/regtest_e2e.sh` for that full ignored suite.

## Fix-round verification (2026-10-03)

No fixture downloads or network access were used during this fix round. The
feature-enabled test binary compiles offline and clippy passes with `-D warnings`.
All six runner tests passed. They cover exit 77 (previously reproduced as a failing assertion),
compilation failure propagation, cleanup, the #200 gate, and main/ghost failures.

The user prohibited **all network access**, including loopback. Cargo tests were
therefore run inside a deny-all-network sandbox. The full `--no-fail-fast` run returned **695 passed, 103 failed, 10 ignored**.
The 103 failures are denied socket operations or consequent setup failures
(including the owner-token shell probe); this is not a green suite. The main regtest
and ghost scenarios were compiled but not executed, and no runtime PASS is claimed.
Missing-fixture runner verification exits 77, and explicitly selecting the Rust
scenario with missing fixtures fails (101). Fixture execution and a green
socket-dependent suite remain blocked by the no-network constraint.


## First CI run correction (run 37117079614, base 359b910)

These root causes are derived from code and the reported failures; the real
regtest runtime was not available for this correction.

1. **Offline quote exposed a product keepalive and reconnect gap.** Raw
   introduction/front-door dials and contacts with `auto_connect=false` had no
   supervisor pings. Both readers expired after 30 seconds. The initial CI
   `Recipient is offline` was a true positive; the harness-only Ping loop masked
   it and has been removed. Every production connection now sends Ping every
   10 seconds on both ends, independently of reconnect eligibility. The read
   future retains its original 30-second deadline, including partial frames;
   outgoing pings do not reset it. Reader completion, replacement, shutdown or
   a failed ping write stops that connection's keepalive. The 429 scenario still
   asserts both original Noise generations across readiness loss and refusal.
   The slow-owner scenario explicitly asserts >30 seconds between quote and
   send, unchanged generations on both ends, and successful paid delivery.
   Transport liveness has no chain-readiness dependency. This does not establish
   the cause of Maya's separate live-run reachability issue.
2. **The ghost bound assumed durable absence evidence.** The existing test already
   passed channel removal, real `/tx/{txid}` 404, provider existence lookup,
   `closing_sats == 0`, and aggregate exclusion before reaching the failed bound.
   In #200, `eligible_package` rechecks funding for every eligible package; its
   absence set is local to that call. A 429 is unknown, never absence. Keeping an
   old 404 indefinitely would prevent recovery if funding arrived later. Once
   eligible, `broadcast_with_backoff` retains the package on 429; queue-level
   30/60/120-second backoff does not count those HTTP retries. Therefore one POST
   per 95 seconds was not #200's contract. Concurrent package responses can extend
   the same shared cooldown episode, so even a per-transaction 10/20/40 schedule
   is not guaranteed. The corrected test separately verifies fresh-404 suppression
   and unknown-funding recovery with the guaranteed 10-second retry floor. It
   logs funding response codes, closed-channel/claim state, POST counts, retry
   gaps and chain health. It requires actual commitment POSTs and a retained retry
   so an idle or lost broadcast worker cannot pass the 429 phase vacuously.

No product readiness or payment gate was relaxed. The source Northstar and
whitepaper are outside this checkout; the supplied doctrine card governs this
change. Doctrine: 1–6 hold; chain availability does not identify or disconnect
mesh peers, keepalives grant no admission, refusals spend nothing, and runtime
success is not claimed.

Verification for this correction used `cargo test --offline --locked -p
konsensus-node --features regtest-e2e --no-fail-fast` under a deny-all-network
sandbox: **695 passed, 103 failed, 10 ignored**, exit 101. Every failure was a
denied socket operation or consequent fixture/setup failure; this is not a green
suite. `cargo clippy --offline --locked -p konsensus-node --all-targets --features
regtest-e2e -- -D warnings` passed under the same sandbox. Cargo still reports the
pre-existing sqlx-postgres future-compatibility notice. Core/electrs runtime tests
were compiled but not run. No network, including port 3141, was contacted.

## Product reconnect policy

- Owner-added contacts default to `auto_connect=true`. All local contacts with a
  usable listening endpoint get supervised reconnects, including legacy entries
  that explicitly store `false`. The field remains accepted for compatibility;
  it is not a reconnect opt-out. Remove a contact to stop its supervision.
  Add, update, import, explicit Connect and node startup use the same supervisor.
  Deletion also removes the persisted contact. Static config entries remain
  owner configuration and must be removed from that file to remove them at boot.
- An introduction/front-door open remains a one-off unprivileged dial. Its
  authenticated, locally supplied endpoint is remembered only in memory while
  connected or needed. It is never put in a contact list or published. The
  supervisor may retry it only while an E2EE session exists, a quote is still
  valid, or a quote/payment operation holds a reconnect handle. Expiring a quote,
  dropping the last operation handle, or removing the session removes that
  reason. A disconnected stranger without any reason is forgotten.
- Retries use exponential backoff from 1 to 60 seconds, respect local bans, and
  have a bounded dial deadline. Repeated registration is idempotent; address
  changes replace the worker; explicit and supervised outbound dials serialize
  by NodeId. Simultaneous inbound/outbound duplicates select the same surviving
  socket at both ends using authenticated NodeId order. Contact removal and
  shutdown cancel pending dials. Each reader and
  keepalive is tied to its connection generation.
- A listening endpoint must be supplied locally. Inbound ephemeral source ports
  and the persisted `0.0.0.0:0` sentinel are never dial targets. An inbound-only
  peer without a known listening endpoint must reconnect from its side; session
  existence cannot manufacture an address. No directory or gossip is used.
- Reconnect restores reachability only. Existing generation-bound quotes, paid
  admission, reservation checks, and single-use recipient-bound payments retain
  their checks. Reconnect never automatically pays or replays an operation.

Doctrine: 1–6 hold for this change: liveness grants no admission or service,
refusals spend nothing, keys remain identity, reconnect reasons and endpoints
stay local, custody is unchanged, and runtime limits are reported explicitly.

## Product-fix verification (2026-10-03)

The final reviewed patch was tested offline under an OS sandbox denying all
network access, including loopback. Across `konsensus-core`, `konsensus-message`,
`konsensus-api`, and `konsensus-node` with `regtest-e2e`, Cargo reported **2,519
passed, 183 failed, 10 ignored** (exit 101). Every failure was a denied socket
operation or a resulting fixture failure. This is not a green runtime suite.
[The verification record](testing/node-liveness-offline.txt) names every failed
test, including the new >60-second acceptor, forced contact redial, stranger
non-redial, live-session/operation reconnect, crossed-dial and cancellation tests.

The socket-free tests passed: the owner-contact default, expiring reconnect
reasons, atomic worker retirement, late shutdown, duplicate-direction selection,
and the unchanged 30-second timeout for silent and partial-frame peers. Clippy
passed offline for all four crates and all targets with `-D warnings`; Cargo
still reports the pre-existing sqlx-postgres future-compatibility notice. The
three-node regtest scenarios compiled but were not executed. No network was
contacted. Independent source review approved the patch after the reported
concurrency and lifecycle findings were resolved.

## Re-admission observer correction (2026-10-03)

Run 37120721675 at `8e1b4b0` passed slow-owner delivery, then timed out in
`eventually(READMISSION)`. In this step that helper only waits for the recipient
socket to disappear (or appear after the explicit dial); it does not wait for a
budget refusal. Slow-owner delivery has already installed the E2EE session, so
Alice's remembered C endpoint remains eligible for supervised redial. A new
connection can be registered between the helper's 250ms polls. The old
`!is_connected` predicate then stays false on a healthy replacement for the
entire 360-second timeout. Nothing in the supplied failure demonstrates lost
E2EE, retired interest, an absent endpoint, or a stuck dial lock. The original
output does not distinguish which of the two re-admission reconnect calls or
which predicate timed out; confirming the runtime interleaving needs CI.

The helper now captures both original connection generations, forces the drop,
and allows either the product supervisor or explicit dial to reconnect. It
requires a different, present generation at **both** ends. It also asserts that
E2EE survives, reconnect spends nothing, and neither replacement inherits paid
admission. The scenario still requires `budget_exceeded` / `first_contact`, no
balance/grant/payment/invoice changes without a recipient allowance, and exactly
4,002 msat (2,001 admission + 2,001 message) with the explicit allowance, including
a second reconnect. The transport regression now checks recipient generation
replacement even when the observer arrives after redial, and loss of the old
paid-admission marker while the E2EE session remains.

Each reconnect is labelled with/without allowance. Before and after the forced
drop, after the explicit dial, every five seconds while waiting, at completion,
and at the refusal/payment boundary, output includes the connection generation,
closed/paid flags, E2EE existence, local supervision endpoint, worker completion,
contact/operation/quote interest, and dial-handle/lock state. These are local,
independently sampled diagnostics, not a public endpoint or an atomic snapshot.

Fable N1 remains: `Connection::register` prefers the lower key's outbound socket
against an opposite-direction candidate until the old socket is locally closed.
A restarted remote can therefore be rejected until read/keepalive detects that
old connection's death (about 30 seconds, plus retry scheduling). This bounded
recovery delay does not itself explain waiting 360 seconds for an absence that
redial already repaired. An unconditional preference reversal would risk
crossed-dial convergence; distinguishing a restart from a concurrent handshake
needs a separately tested liveness/incarnation design. No arbitration change is
included in this test correction.

Doctrine: 1–6 hold. Payment and admission gates are unchanged, refusals spend
nothing, keys identify peers, diagnostics and reconnect interest remain local,
custody is unchanged, and CI runtime recovery remains to be verified.

Final offline checks for `konsensus-message` and `konsensus-node` with
`regtest-e2e`: **930 passed, 169 failed, 10 ignored**, exit 101, under an OS sandbox
denying all network including loopback. Failures were socket-denied setup or
consequent fixture failures; the strengthened live-session reconnect regression
failed at listener bind. [The verification record](testing/readmission-offline.txt)
names every failure. Clippy passed offline for both crates/all targets with
`-D warnings`; the existing sqlx-postgres future-compatibility notice remains.
Source review approved the code change. Core/electrs runtime was not run and no
network was contacted.

## Hub LSPS2 provider

The same entry point also runs
`regtest_e2e::three_node::lsps2_service::hub_jit_then_stateless_admission`:
three production `LdkProvider` nodes (sponsor → hub → app), no pre-opened app
channel, existing LSPS2 client negotiation, a JIT top-up within 60 seconds, then
separate stateless admission payments from and to the app. Assertions cover the
opening fee, inbound from overprovisioning, positive hub forwarding fees within
the ALL-IN allowance, no admission skim, disconnected-provider refusal and
post-restart tariff recovery. The client's on-chain anchor reserve is funded;
the test does not claim an empty wallet can receive an anchor channel.

Run only this case with the usual fixture environment:

```sh
REGTEST_TEST=regtest_e2e::three_node::lsps2_service:: \
  scripts/regress/regtest_e2e.sh
```

See [hub and app config examples](LSPS2-LIQUIDITY.md#hub-provider-pilot) for the
opt-in service. The #190 funding policy and vendor code remain unchanged.
