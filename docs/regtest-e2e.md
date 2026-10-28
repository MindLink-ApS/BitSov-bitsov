# Real LDK regtest regression (REGTEST-E2E)

For the Atlas TEST5 robustness lane (three application nodes, remote spend
elevation, sender/recipient 429, restart, quote expiry and stale peer pricing), use
[`scripts/regress/three_node_paid_e2e.sh`](three-node-paid-e2e.md). The existing
routed scenarios below retain their assertions.

This opt-in test runs real LDK nodes, Bitcoin Core regtest, Noise transports,
the production session/message handlers, and the production Axum routes. It
uses temporary SQLite stores and paired-client spend grants. No mock Lightning
or chain provider is involved. API requests run in-process; Axum's
`MockConnectInfo` supplies loopback connection metadata only.

**Status at `e3c0633` (#100 merged): the complete scenario passes** on real
LDK: first contact, paid follow-up, paid reply, over-ceiling refusal, fee-capped
payment and msat reconciliation (about 48 s after the build).

## Topology

```text
A (BitSov app + LdkProvider) ── private ── C (routing-only ldk-node) ── private ── B (BitSov app + LdkProvider)
```

There is no A–B channel: every A↔B payment pays C's positive forwarding fee
(LDK default 1,000 msat base, 0 ppm, read from C's channels at runtime and
cross-checked with the policy A and B received). A opens A→C through
`LdkProvider::open_channel` (supported path, no explicit rate); C opens C→B.
All three wallets are funded on-chain before opening: B needs its anchor reserve
even though C provides the Lightning channel capacity.

C is built directly on `ldk-node`, not `LdkProvider`. Stock LDK refuses to
forward into an unannounced channel (`PrivateChannelForward`) unless
`accept_forwards_to_priv_channels` is set, which ldk-node 0.7 does only for an
LSPS2 service or an async-payments server. A BitSov node can only hold private
channels (`LdkConfig` has no node alias), so C runs in LSPS2-service mode, the
role an LSP plays for a private BitSov node. No client requests a JIT channel;
the service role only enables forwarding.

## Production private hub regression (#225)

`private_forwarding::production_hub_private_forwarding_is_opt_in` adds a
separate A→hub→B scenario built entirely through `LdkProvider::new`, including
the hub. It uses no LSPS2 service, alias, or announced channel. Fresh topologies
exercise both settings: the default rejects a dispatched payment with
`PrivateChannelForward`; the opt-in settles at both endpoints and charges the
hub's exact positive forwarding fee. It also checks the invoice's private route
hint so a missing route cannot masquerade as the expected rejection.

To enable routing on a production private hub, add this to its existing LDK
configuration and restart the node:

```toml
[lightning]
backend = "ldk"
forward_to_private_channels = true
```

What this changes for that hub: payments between its peers can route through it, so its
channel balances move and may need rebalancing; payers can probe it (coarse capacity of
its private channels becomes inferable); forwarded HTLCs hold liquidity until settled or
timed out, within LDK's CLTV and in-flight limits; and it charges LDK's default
forwarding fee. Nothing is announced, and it never spends its own funds without a
matching incoming HTLC. Enable it only on the node that acts as the hub.

Omitting the flag or setting it to false retains existing behavior. This setting
does not announce the node or its channels. The older LSPS2-backed scenario
above remains as separate coverage. The scheduled/manual three-node paid regtest
workflow runs this new scenario explicitly before its paid-flow tests.

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

For LDK/app detail on a failure:

```sh
RUST_LOG=konsensus=debug,konsensus_api=debug,konsensus_message=debug \
REGTEST_TEST=regtest_e2e::real_ldk_regtest_e2e scripts/regress/regtest_e2e.sh
```

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
  timeout, SIGINT, SIGTERM or SIGHUP sent to the runner PID or process group,
  and removes its temporary root. Rust owners also stop/wait daemons and remove
  data on ordinary completion/panic. The build
  cache remains. Default overall timeout is 900 seconds including compilation;
  override `REGTEST_TIMEOUT_SECONDS`. Timeout exits 124.

Check runner cleanup without building Rust or starting Bitcoin Core/electrs:

```sh
python3 scripts/regress/test_regtest_e2e_runner.py -v
```

This exercises successful/failed exits, timeout, and each cancellation signal
sent to the runner PID and process group, including cancellation during child
launch. It checks that the supervisor, fake Cargo, and daemon descendants
(including SIGTERM-resistant children) exit and the disposable data root is
removed.

## Steps and assertions

1. **#101 refusal:** `open_channel(.., Some(3.0))` returns
   `PaymentNotDispatched("LDK cannot enforce an exact caller-supplied funding fee rate; use funding_priority")`,
   with no channel and an empty mempool.
2. **Channels:** A→C and C→B at 1,000,000 sat via the estimator (156 sat /
   153 vB each), six confirmations, usable on both ends; on-chain change checked.
3. **Reply liquidity:** 50,000,000 msat routed A→C→B with a fee cap of exactly
   C's fee; the settled fee equals C's policy.
4. **Stateless quote:** 2,001 admission + 2,001 message + 10,000 aggregate fee
   ceiling = 14,002 msat; no invoice record, no budget debit. Owner grants it.
5. **First contact:** admission then real X3DH/ratchet; B decrypts the first
   message; the raw admission marker is not delivered as content.
6. **Paid follow-up** A→B, decrypted by B.
7. **Unlisted reply refused:** per #100, the payer side accepts only the bought
   session frames; `RequestInvoice` stays privileged-only. B's reply to an
   unlisted A is a first contact of its own: 409 `first_contact`, nothing paid.
8. **Paid reply:** A's owner lists B (`POST /api/v1/peers`), which privileges the
   live connection; B pays the message price only; A decrypts it.
9. **Over-ceiling refusal:** a 2,001-msat B invoice paid through
   `/api/v1/payments/pay` with `max_routing_fee_msat` = C's fee − 1. A route
   exists but costs more: 400 with `code: "not_dispatched"` and the effective
   `max_routing_fee_msat`, budget unchanged
   (reservation released), A's record `Failed`, B's `Pending`, A's channel unchanged.
10. **Fee-capped payment:** same route, cap = C's fee exactly: settles.
11. **Reconciliation (msat-exact):** channel outbound capacities A −(4×2,001 +
    4×1,000) + 2,001, B +4×2,001 − (2,001 + 1,000), C +5,000; every settled
    Lightning record has the expected amount, fee and SHA256(preimage) = hash;
    A's on-chain funding record is 1,000,000 sat with the measured funding fee;
    paired budgets A 12,004 msat and B 3,001 msat (principal + actual fee).

`real_ldk_predispatch_refusal` remains as a separate **no-route** control:
2,001 msat + 37 msat reservation released with no channels at all. It polls
the payer's `money_ready` state with a bounded wait before attempting payment,
so asynchronous wallet sync cannot turn the expected refusal into a 503.

## Differences from the shared mock

| Behavior | Real LDK observation |
| --- | --- |
| Explicit funding rate | Refused pre-dispatch (#101); only the estimator path opens channels. |
| Funding cost | Actual on-chain fee (156 sat / 153 vB per channel); absent from mock accounting. |
| Channel readiness | Needs wallet/indexer sync, mined confirmations and `is_usable` on both ends. |
| Inbound anchor channel | An unfunded acceptor refuses an inbound anchor channel (`0/25000 sats` reserve) unless the selected-provider reserve waiver applies. The non-anchor retry is also refused; legacy fixtures must fund the acceptor before opening. |
| Forwarding | Private-channel forwarding needs LSPS2-service/async-server mode on the router. |
| Routing fees | Positive (1,000 msat per 2,001-msat payment through C); the mock routes at zero. |
| Immediate payment result | In flight, no preimage/fee yet: `/payments/pay` and `/payments/keysend` answer `202` with `status: in_flight` after a short settlement wait; repeat with the same `request_id` or poll `GET /payments/{hash}` until `200 settled` (see `docs/v2/API_PAYMENTS.md`). |
| Reply liquidity | Needs real outbound liquidity above the channel reserve. |
| First contact latency | ~16 s for admission + session + first message; later messages ~2 s. |
| Payment list | `list_payments` includes on-chain funding/receipts as hashless records. |
| Precision | `get_balance_msat` is whole-satoshi; exact accounting uses records and channel capacities. |

## Non-dispatch API contract audit (2026-09-28)

`LightningError::PaymentNotDispatched` now survives the shared `ApiError`
conversion as HTTP 400 with `code: "not_dispatched"` and the backend reason.
`/payments/pay` and `/payments/keysend` retain `max_routing_fee_msat`, including
zero; their metered reservations are released as before. `/payments/close-channel`
inherits the shared mapping, `/payments/open-channel` already maps explicitly,
and `/payments/send-onchain` now preserves the code in its custom error match.
The shared conversion (including pay/keysend, open-channel and send-onchain)
keeps ambiguous Lightning errors at 502; readiness remains 503 `not_ready`.
Local channel/on-chain fee validation and LDK on-chain address/fee preflight
return `not_dispatched` before invoking the wallet. An unclassified wallet
error remains ambiguous, regardless of its text. On-chain
`BroadcastUnconfirmed` remains 202 with its transaction ID.

Other generic conversion sites were audited: liquidity quote/accept, invoice
creation, payment status/liquidity receipt, balances, channel/payment lists,
and sponsor claim invoice creation all inherit the typed mapping. Liquidity
accept's synchronous quote lookup still reports bad input as generic 400;
it occurs before the debit or publication. Its asynchronous accept call
releases proven non-dispatch reservations and now preserves the code.

Message compose preserves typed invoice/admission refusals and the operation
ID, state and effective fee ceiling. The operation journal clears only a
proven undispatched attempt; its exact reservation is released and recovery
cannot apply that release to a later attempt. An uncertain message or admission
keeps its reservation and returns 502. If admission already settled, a later
message refusal remains `payment_settled_send_incomplete` (502), with admission
still charged; it never claims aggregate non-dispatch. Compose's keysend
fallback continues to require positive non-dispatch evidence.

Sponsor approval records and resolves the exact kit before returning
`not_dispatched` for a proven refusal. A dispatched terminal failure remains
502 without that code. Ambiguous backend errors return 502 and retain the
kit's purse hold across restart; callers reconcile that kit instead of
approving it again. Successful provider responses with a pending/unknown
payment record keep the existing response body and held reservation.

**bitsov-app needs a separate mapping PR.** At app main `e151910`,
`src-tauri/src/main.rs`'s spend path recognizes readiness, grant and price-cap
refusals, but all other non-success responses become unknown-spend journals
(around lines 2330–2377). Even the corrected 400 will stay locked until the
app recognizes the structured `not_dispatched` contract, releases its local
reservation and abandons the journal. That change should test invoice pay
and keysend, allow a subsequent spend, and retain journals for ambiguous
502 responses. No app behavior is changed by this genome PR.

The production [hub LSPS2 regression](three-node-paid-e2e.md#hub-lsps2-provider)
now exercises actual JIT service/client negotiation, overprovisioning and
stateless admission with a configured positive forwarding tariff. It is separate
from the legacy routing-only service fixture and the #225 opt-in control above.

## Option A Phase 0: starter liquidity PASS markers

Four ignored `regtest-e2e` tests in `three_node::lsps2_service::phase0_*`
exercise production `LdkProvider` selection and push funding with fresh clients.
Only the hub receives on-chain funds. Run with the same Core/electrs prerequisites
and isolated runner described above:

```sh
BITCOIND_EXE=/path/to/bitcoind ELECTRS_EXE=/path/to/electrs \
REGTEST_TEST=regtest_e2e::three_node::lsps2_service::phase0_ \
  scripts/regress/regtest_e2e.sh
```

Acceptance target: **4 passed, 0 failed**, with these `PHASE0 PASS` markers:

- `push-zero-conf`: a private 100,000-sat channel pushes 10,000 sats to a
  zero-sat on-chain wallet. Both ends are usable with zero required/actual
  confirmations and funding still in Core's mempool. Spendable outbound is
  approximately 10,000 sats, less the negotiated channel punishment reserve;
  outbound plus that reserve equals the push exactly.
- `connect-reuse`: the client has no listener and initiates the LN connection.
  The hub opens using `127.0.0.1:0`, which fails to connect before the client's
  connection exists. `vendor/ldk-node/src/lib.rs::open_channel_inner` already
  calls `connection.rs::connect_peer_if_necessary`, which returns before
  dialing an already connected peer. **No vendor patch is needed.**
- `spend-push`: the client pays the hub 1,000 sats from its pushed balance,
  settling at both ends with zero routing fee before any confirmation.
- `reject-opt-out`, `reject-non-selected`, `reject-above-cap`: fresh empty
  clients reject for insufficient anchor reserves when trust is false, the
  opener is not selected (even with its own trust flag true), or the selected
  trusted opener offers 200,001 sats. Each asserts the explicit reserve refusal,
  no surviving channel and no funding broadcast.

No blocks are mined after opening in any scenario. This is a regtest proof for
the signet-first design, not a signet deployment or an app/message test. Startup
provider connection (N2), N3 and hub H1–H6 remain out of scope.

**Observed on 2026-10-20 after the Atlas ruling: 4 passed, 0 failed.** All four
Phase 0 items pass, including all three negative controls' unchanged final
rejection, no-surviving-channel and no-funding-broadcast assertions. The positive
scenario has 9,000 sats spendable plus 1,000 sats punishment reserve.

BitSov now refuses every non-anchor inbound channel in the vendored
`OpenChannelRequest` handler, next to the anchor-reserve check. This includes
originally non-anchor requests and LDK's `maybe_downgrade_channel_features`
retries after an anchor refusal: the retry cannot bypass the reserve-waiver
gate. The rule applies to clients and services alike. The 200,000-sat cap,
selected-provider `trust_no_reserve` semantics, zero-conf trust and outbound
anchor defaults are unchanged. The global inbound rule removes the previous
non-anchor fallback for empty-wallet clients and for external non-anchor-only peers.

The full `regtest_e2e::three_node::lsps2_service::` module also passes:
**5 passed, 0 failed**, including hub JIT funding, disconnect/restart recovery
and stateless admission. No service exception is used. Legacy routing, paid-flow,
payment, wallet-move and recovery fixtures now fund acceptors on-chain before
channel admission; the Phase 0 tests and existing LSPS2 service fixture are unchanged.
The vendored LDK Node library suite passes **166 tests**, including a new
runtime regression that rejects non-anchor requests from trusted peers, removes
the pending request and preserves anchor acceptance with and without zero-conf
trust.

The run also exposed a funding-result bug: the production opener returns
`UserChannelId(n)` but reconciliation parsed it as bare decimal. Reconciliation
now shares close's existing ID parser, with a round-trip regression test. This
fix enables the production push API to report its actual funding outcome; it
does not change channel selection or reserve policy.
