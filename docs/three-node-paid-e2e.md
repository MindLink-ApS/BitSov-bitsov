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

The ghost/unfunded-channel scenario is separately ignored with the reason
**requires unmerged PR #200**. This branch still checks `/tx/{txid}/status`, which
can return `200 {"confirmed":false}` for an unknown transaction, and lacks the
absent-parent rebroadcast suppression that scenario requires. The default wrapper
prints this scoped SKIP; it does not claim ghost coverage. After #200 merges, use:

```sh
REGTEST_GHOST_AFTER_PR200=1 scripts/regress/three_node_paid_e2e.sh
```

The dispatch workflow exposes the same named gate. With it enabled, both scenarios
must run and pass; no failure is swallowed. Until #200 merges, nightly runs cover
the paid-flow lane and explicitly report the ghost subscenario as skipped. Enable
the gate by default in the wrapper/workflow when landing #200.

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
| Run 4 step 6: stale sender price table | B sends a height-0 table with price 999,999. A's real `/pricing/peers` response must flag it stale; a first-contact quote must return the target's fresh 2,001 price within 8 seconds with no payment or payable invoice. A subsequent real wire update must appear fresh on the same endpoint. The endpoint reports freshness; it does not itself fetch a replacement table. The recipient backend failure path is the typed `peer_not_ready` scenario above, not a compose-price assertion. |
| Sender-side 429 | A's chain/LDK backend is limited. Compose must return local `503 not_ready` within 8 seconds without budget, capacity or invoice changes; background recovery must permit another 2,001-msat paid message. |
| Slow owner approval | C's first-contact quote ages beyond its signed absolute TTL before the owner approves through the real socket. Sending must replace the expired quote and deliver, with exactly two settled payments (one admission and one message) and a 4,002-msat debit. This proves no duplicate paid admission, not an exact count of unpaid wire requests. |
| Grant without recipient entries, reconnect | A's original grant has an empty recipient map; both first-contact approvals omit a contact budget. After C reconnects, compose must return `409 budget_exceeded`, reason `first_contact`, without any payment, invoice or budget change. The owner revokes that grant and issues explicit B/C recipient entries via the socket. Re-admission then costs exactly 4,002; a further reconnect pays the same amount without another owner confirmation. |
| Ghost channel (gated on #200) | Drop actual funding broadcasts before they reach Core, retain the real LDK monitor, force-close the unfunded channel, prove real `/tx/{txid}` returns 404, observe the provider querying that existence endpoint, and assert `closing_sats == 0` and aggregate exclusion despite a nonzero raw monitor claim. After initial processing, observe 95 seconds (three 30-second LDK rebroadcast ticks) under 429: at most one additional commitment POST is allowed. |
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
