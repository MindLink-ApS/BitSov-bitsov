# Real LDK regtest regression (REGTEST-E2E)

This opt-in test runs two real `LdkProvider` instances, Bitcoin Core regtest,
Noise transports, the production session/message handlers, and the production
Axum routes. It uses temporary SQLite stores and paired-client spend grants.
No mock Lightning or chain provider is involved. API requests run in-process;
Axum's `MockConnectInfo` supplies loopback connection metadata only.

**Status at base `dac01c8`: the requested complete scenario is blocked.**
The strict test is intentionally red at the explicit funding-fee request.
A diagnostic mode reproduces a separate paid-first-contact E2EE failure.
Neither is a successful end-to-end run. The paid follow-up, B reply, and final
message balance assertions exist but cannot yet be reached on this base.

## Run

Prerequisites: Rust/Cargo, Python 3, Bitcoin Core, and the Esplora-compatible
Blockstream electrs binary used by the existing LDK integration harness
(`esplora_a33e97e1a1fc63fa9c20a116bb92579bbf43b254`). Ordinary electrs without
its HTTP/Esplora interface is not sufficient. Cargo dependencies must already
be cached: the runner uses `--offline --locked` and enables no download feature.

```sh
scripts/regress/regtest_e2e.sh
```

The runner checks `BITCOIND_EXE` / `ELECTRS_EXE`, then PATH, then existing
`/tmp/bitsov-target-*/debug/build/*/out/` harness caches. It prints the selected
executables. Explicit paths are preferable in CI:

```sh
BITCOIND_EXE=/path/to/bitcoind ELECTRS_EXE=/path/to/electrs \
  scripts/regress/regtest_e2e.sh
```

Default build cache: `/tmp/bitsov-target-a22`; override `CARGO_TARGET_DIR` if
needed. The runner disables debug symbols and incremental compilation to
limit disk usage. Normal test runs ignore these tests. To run only the
pre-dispatch reservation control:

```sh
REGTEST_TEST=regtest_e2e::real_ldk_predispatch_refusal \
  scripts/regress/regtest_e2e.sh
```

To investigate messaging beyond the unsupported explicit fee request:

```sh
RUST_LOG=konsensus=debug,konsensus_api=debug,konsensus_message=debug \
REGTEST_TEST=regtest_e2e::real_ldk_regtest_e2e \
REGTEST_DIAGNOSTIC_ESTIMATED_FEE=1 scripts/regress/regtest_e2e.sh
```

That diagnostic first asserts the explicit request was refused before a
channel/funding transaction exists, then opens using LDK's estimator. It
prints `DIAGNOSTIC ONLY` and must not be used to claim explicit-rate support.

No binaries were downloaded for this work: Bitcoin Core 28.2 and the electrs
binary were already present in the existing `bitsov-target-a13` harness cache.
The runner never downloads executables. If provisioning Core separately, use
only the official release archive and its `SHA256SUMS` from
<https://bitcoincore.org/bin/>, verify the archive checksum before extraction,
and then set `BITCOIND_EXE`. Do not enable an arbitrary download mirror or
substitute an unverified archive.

## Isolation and lifecycle

- Bitcoin Core is hardcoded to regtest, disables P2P listening, DNS seeds and
  discovery, disables network activity entirely, and binds RPC to `127.0.0.1`.
  It mines 101 blocks to mature coinbase.
- LDK, Noise, electrs HTTP/Electrum/monitoring all bind `127.0.0.1` on ephemeral
  ports. There are no seed peers, public chain endpoints, RGS servers or LSPs.
- The existing `corepc-node` process/data-directory harness is reused.
  `electrsd` itself is not used because its listeners are hardcoded to
  `0.0.0.0`; the runner uses its already cached binary with explicit loopback
  arguments. A loopback HTTP adapter strips the application chain provider's
  `/api` prefix and forwards real electrs responses; fixture startup asserts
  its height equals Bitcoin Core RPC. The RPC wallet is created through raw
  JSON: the harness's default wallet wrapper failed with the cached Core 28.2,
  whereas the raw RPC succeeded.
- The supervisor clears inherited HTTP/HTTPS/ALL proxy settings and forces
  proxy bypass. It owns a new process group, kills remaining children on exit,
  timeout, SIGINT or SIGTERM, and removes its temporary root. Rust owners also
  stop/wait daemons and remove data on ordinary completion/panic. The build
  cache remains. Default overall timeout is 900 seconds including compilation;
  override `REGTEST_TIMEOUT_SECONDS`. Timeout exits 124.

## Assertions and observed blockers

The strict scenario funds A with 3,000,000 sat from regtest coinbase and asks
A to open a private 1,000,000-sat channel to B at **3 sat/vB**. If supported,
the test checks the actual funding transaction's mempool fee/vsize, mines six
confirmations, waits for both channel endpoints to become usable and checks
A's on-chain change against the actual funding fee.

At `dac01c8`, `open_ldk_channel` deliberately rejects every explicit fee rate:

```text
payment not dispatched: LDK cannot enforce a per-channel funding fee rate
```

This is #101's fail-closed behavior, not a harness/network failure. The pinned
LDK API exposes no per-channel funding-fee override. The diagnostic estimator
run paid **156 sat for 153 vB**, rather than the requested 3 sat/vB.

For reply liquidity the test transfers 50,000,000 msat from A to B over the
real channel. Merely receiving a few sats does not clear B's channel reserve.
This transfer does not admit either application identity. The test polls both
payment records to settlement and checks channel liquidity before starting
Noise first contact.

Both application nodes start with empty whitelists and no E2EE session. The
stateless quote produces no persisted Lightning invoice record or budget debit.
Observed quote: **2,001 msat admission + 2,001 msat message + 10,000 msat
aggregate maximum routing fees = 14,002 msat**. The test grants this exact
quote through the owner route, then composes with a zero routing-fee ceiling.

The admission settles for **2,001 msat** and B's real payment gate promotes A.
However, A drops B's prekey offer as unpaid. `mark_admission_paid` only sets
`admission_paid`; A's view of B remains `privileged=false`. Both the incoming
session gate and A's self-heal exclude B. Compose returns HTTP 502 with
`payment_settled_send_incomplete` after the **25-second E2EE timeout**.
This is a reproducible base-code defect; the fixture does not preinstall a
session or whitelist B to hide it.

After these blockers are fixed, the existing assertions require:

1. Admission followed by the real X3DH/ratchet handshake and decrypted first
   message; the raw admission marker is distinguished from message delivery.
2. A second paid message and B's paid, decrypted reply, with ciphertext unequal
   to plaintext.
3. A's message/admission spend of **6,003 msat**, B's reply spend of **2,001
   msat**, and exact channel-capacity changes **A −4,002 / B +4,002 msat**.
4. Matching paired-budget debits, settled outgoing records with zero direct
   routing fees, and SHA256(preimage) equal to each payment hash. Funding fees
   are checked separately from Lightning fees.

## Fee-cap coverage boundary

`real_ldk_predispatch_refusal` creates a real B invoice before either node has
channels and submits it through A's metered payment API with a 37-msat fee
ceiling. It requires LDK's `PaymentNotDispatched`, a failed sender record, an
unpaid recipient record, zero balance movement, and release of the entire
**2,001 + 37 msat** reservation.

This is a **no-route control**, not proof that an available route exceeded the
fee ceiling. A direct A→B channel has no forwarding hop/fee. A real positive
forwarding-fee probe needs an additional local Lightning routing node and a
positive-cap success control; that topology extension was requested for
clarification and is not included. The over-ceiling acceptance criterion
remains unverified. No synthetic graph, fabricated route, or mock dispatcher
is substituted for it.

## Differences from the shared mock

| Behavior | Real LDK observation |
| --- | --- |
| Explicit funding rate | Refused pre-dispatch; estimated-rate diagnostic is separate. |
| Channel readiness | Requires wallet/indexer sync, mined confirmations and `is_usable` on both ends. |
| Immediate payment result | `Pending`, no preimage/fee yet; terminal settlement must be polled. |
| Reply liquidity | Needs real outbound liquidity above the channel reserve. |
| First-contact E2EE | Exposes asymmetric privilege bug hidden by fixtures that preinstall E2EE sessions. |
| Funding cost | Actual on-chain fee (observed 156 sat); absent from shared mock accounting. |
| Precision | LDK's aggregate `get_balance_msat` converts whole-satoshi balances; exact sub-sat accounting must use settled payment records and channel-capacity deltas. |
| Routing-fee refusal | Real no-route reservation release is separately tested; a two-node direct route cannot demonstrate a positive forwarding fee. |

## Verification recorded on 2026-09-28

- Strict invocation: one real no-route control passed; explicit-fee scenario
  failed before opening a channel.
- Messaging diagnostic: failed after settled admission and the 25-second
  E2EE wait, including after fixing and verifying the chain URL adapter.
- Node test suite: 487 passed, 3 ignored (including these two opt-in tests).
- Clippy with `-D warnings`, Rust formatting, shell syntax and diff checks
  passed. Cargo reports the existing `sqlx-postgres 0.8.0` future-compatibility
  warning.
- Success, assertion-failure and forced-timeout runs left no disposable root
  directories or matching daemon processes. Timeout returned 124.
