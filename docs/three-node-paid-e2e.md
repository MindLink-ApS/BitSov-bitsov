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

The entry point runs only
`regtest_e2e::three_node::three_node_paid_e2e`, offline and locked, with one test
thread. It inherits the existing process-group supervisor: cancellation, panic,
failure and timeout clean up Core/electrs and temporary data. Default total
timeout is 1,800 seconds including compilation; override
`REGTEST_TIMEOUT_SECONDS`. `RUST_LOG=konsensus=debug,konsensus_api=debug` adds
protocol detail.

If either fixture is unavailable, the entry point **still compiles the enabled
test binary**, then prints `SKIP three-node paid E2E` and exits zero. Compilation
failure stays nonzero and never prints a successful skip. CI must distinguish
that SKIP from the scenario's `THREE-NODE PAID E2E PASS`; provision executable
fixtures in CI jobs that require runtime coverage. Directly selecting the ignored
test without fixture paths also reports a clear SKIP. A failed fixture startup
or any assertion failure is a failure, never a skip.

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
         local HTTP 429 proxy
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
| Run 4 steps 1,3: 429 and 30-second silence | B's application chain provider **and** real LDK use the HTTP fault proxy. While it returns 429, wallet readiness expires and sync reports stalled. A receives `503 peer_not_ready`, `retry_allowed: true` within 8 seconds, with no invoice records/payment. The peer wire refusal is `konsensus:not_ready:…`; the API preserves recipient context with `peer_not_ready`. Restoring HTTP success must clear sync failure, restore readiness and catch B up to a newly mined block within 180 seconds, without restarting B or manually syncing its wallets. |
| Run 4 step 3: mixed-version height-0 price table | B sends a real `PriceTable` wire frame with height 0, one-block validity and a deliberately wrong price. A must cache but reject it as stale; the next delivered message settles at the equal configured fallback price (2,001 msat), rather than the injected 999,999-msat price. This emulates the observed older-node table, not arbitrary binary-version compatibility. |
| Run 4 steps 2–3: recipient restart during active client flow | B closes/reopens its existing wallet and stores; mesh key, LN key, channel IDs and encrypted session survive. A keeps its client/grant, reconnects, and pays for another delivered message. |
| Run 2 #14–18: room flow blocked | A fans out a room message to B+C; two settled member receipts, 4,002-msat budget debit, known zero routing fee, two decrypted recipient-bound envelopes. |

The original routed positive-fee, no-route, call, meeting and room tests are
unchanged; use `scripts/regress/regtest_e2e.sh` for that full ignored suite.

## Verification on the implementation host

On 2026-10-03, the feature-enabled `konsensus-node` suite passed offline:
798 tests passed, 9 remained ignored (the eight opt-in regtest scenarios and the
existing DBH1 recovery test). Clippy with `--all-targets --features regtest-e2e
-- -D warnings` passed offline. All four Python runner tests passed, including
successful/failed build-only skips and cleanup on success, failure, timeout and
cancellation. The new proxy regression ran against ephemeral loopback HTTP.
The suite needed local-socket permission: the initial sandboxed attempt refused
five existing STUN tests at loopback UDP bind; the permitted rerun passed.

The new entry point compiled and reported SKIP because this host has neither
local Bitcoin Core nor electrs. No three-node regtest runtime PASS is claimed;
no binaries were downloaded and no public network or port 3141 was contacted.
