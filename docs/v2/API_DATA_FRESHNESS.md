# Data freshness headers (G-STALENESS-MARKER)

Six read routes tell the caller how old the data in the response is, so a
client can tell "the node answered just now" apart from "the node's figures
are current". Code: `crates/konsensus-api/src/freshness.rs`. Tests:
`crates/konsensus-api/tests/data_freshness_tests.rs`.

## Headers

```
BitSov-Data-As-Of: 2026-09-27T08:20:00Z
BitSov-Data-Stale: 1
```

**`BitSov-Data-As-Of`** — the oldest "last known current" time among the
sources the handler used for this response.

- RFC 3339, always UTC written as `Z`, whole seconds (fractions truncated,
  never rounded up). Exactly 20 ASCII characters.
- Node clock. Clamped to the node's "now" at response time, so it is never in
  the future from the node's point of view. A client whose clock differs from
  the node's must apply its own skew handling.
- Absent when the node has no time for the data (see per-route table).

**`BitSov-Data-Stale`** — present, with the value `1`, only when the node
itself judges the data past its freshness bound. Absent means "not known
stale", **not** "fresh". No other value is ever sent.

Stale data is still served with `200` and the unchanged body. The node does
not turn stale data into an error; that is the client's decision.

## Per route

| Route | `BitSov-Data-As-Of` | `BitSov-Data-Stale: 1` when |
|---|---|---|
| `GET /api/v1/payments/balance` | Wallet sync time (below) | wallet sync ≥ 10 min old, or never synced |
| `GET /api/v1/payments/channels` | Wallet sync time (below) | wallet sync ≥ 10 min old, or never synced |
| `GET /api/v1/health` | Time the chain backend was queried for `block_height` (a live query per request). **Absent** when `block_height` is null (query failed) | never |
| `GET /api/v1/messages` | Time the local message store was read for this response. The store is the node's own and authoritative, so this is "read just now", present for uniformity | never |
| `GET /api/v1/pricing` | Chain-aware engine: the oldest real chain fetch among the values being served (each per-target fee rate and the block height); a value reused after a failed fetch keeps its old time. Static engine: time of the read (static prices do not depend on chain data) | chain-aware only: that oldest fetch is at or past the engine's `cache_ttl` (default 60 s), or there is no cached state |
| `GET /api/v1/peers` | Time the node's peer registry and live connection set were read for this response. Both are the node's own, so this is "read just now"; a client answer that lists peers (for example the app's spend answer) can then state its age | never |

### Wallet sync time (`/payments/balance`, `/payments/channels`)

From `LightningProvider::wallet_sync()`:

- **LDK** (embedded): the older of `latest_lightning_wallet_sync_timestamp`
  and `latest_onchain_wallet_sync_timestamp` from `Node::status()`; the balance
  sums both wallets, so it is only as current as the older sync. Until both
  wallets have synced once: no `As-Of`, and `Stale: 1`.
  Stale bound: 10 minutes (`WALLET_SYNC_STALE_AFTER`). LDK's background sync
  runs every 30 s (Lightning) / 80 s (on-chain) by default, so 10 minutes is
  several missed syncs, e.g. the chain backend has been unreachable.
- **LND, mock** (and legacy LNbits code paths if ever forced in tests; LNbits is not selectable after #99/#104) (query the backend on every call): the time just before
  the backend was asked. Never stale.

The sync status is read *before* the balance/channel read, so the header
never claims the figures are newer than they are.

### Wallet balance breakdown (G-safety, #176)

`GET /api/v1/payments/balance` requires `read` scope and now returns optional
top-level categories alongside the unchanged `balance_msat`. This is a local
wallet observation through the existing authenticated API, not a peer service,
payment, or money-moving operation. It uses the same freshness headers above.

| Field | Meaning for the embedded LDK provider |
|---|---|
| `balance_msat` | Legacy aggregate, unchanged: `(total_lightning_balance_sats + spendable_onchain_balance_sats) * 1000`. Includes Lightning claims that cannot currently be spent. Other providers retain their existing semantics. |
| `onchain_spendable_sats` | On-chain funds LDK considers spendable after confirmation requirements and the anchor reserve. |
| `onchain_total_sats` | Total on-chain wallet funds, including unconfirmed funds and the anchor reserve. |
| `anchor_reserve_sats` | On-chain funds reserved for anchor-channel closing fees, already included in `onchain_total_sats`. |
| `lightning_spendable_sats` | Sum of `outbound_capacity_msat` for `is_usable` channels, divided by 1000 and rounded down after summation. Excludes channel reserves, pending HTLCs, and inactive channels. This is outbound capacity, not a promise that a payment of that amount can route: routing fees, per-HTLC limits, and remote liquidity still apply. |
| `closing_sats` | `ClaimableAwaitingConfirmations` (including timelocks), plus `ClaimableOnChannelClose` for channels no longer in the channel manager (for example, a force-close not yet confirmed), plus every pending sweep variant: `PendingBroadcast`, `BroadcastAwaitingConfirmation`, `AwaitingThresholdConfirmations`. An open channel with a disconnected peer is not counted as closing. |
| `contested_sats` | Potential claims from `ContentiousClaimable`, `MaybeTimeoutClaimableHTLC`, `MaybePreimageClaimableHTLC`, and `CounterpartyRevokedOutputClaimable`. Conditional claims are not guaranteed wallet funds or spendable liquidity. |

Unknown categories are **omitted**, never replaced with `0` or `null`. A known
empty category is `0`. Providers without breakdown support (currently LND,
LNbits, and mock) omit all six new fields. Backend failures remain errors;
the recovery wrapper still returns `not_ready` until its backend is ready.

The live embedded API stack is `GuardedLightning -> RecoveringLightning ->
LdkProvider`. Both wrappers forward the breakdown read, including when the disk
guard refuses new money-moving work. `CircuitBreakerLightning` also forwards
the read; the node uses that wrapper separately for inbound settlement
verification. The node regression tests in
`crates/konsensus-node/src/tests/balance_breakdown.rs` exercise the authenticated
API through the live API stack and through all three wrappers, including low
disk conditions.

These fields are **not an additive partition of wallet wealth**. Pending sweep
amounts are before sweep fees and, depending on wallet sync, may already be in
the on-chain total. LDK retains confirmed sweeps for reorg safety even when
their proceeds are spendable. Therefore `closing_sats` describes the tracked
closure/sweep pipeline, not an exact amount unavailable on-chain. Never add it
to `onchain_total_sats` or subtract it from `onchain_spendable_sats`. Normal open
channel reserves are also not a separate category here. Balances and channels
are separate local snapshots and can change during a read; clients should use
the freshness headers and refresh after channel transitions.

In particular, `lightning_spendable_sats + closing_sats + contested_sats +
onchain_spendable_sats` need not equal `balance_msat / 1000`. Usable outbound
capacity differs from LDK's claimable balance; claims in listed but unusable
channels are not spendable or closing. The contested category includes
conditional HTLC claims that LDK excludes from its legacy aggregate, and the
closing category includes pending sweeps that are absent from the aggregate's
Lightning component. These categories cannot reconcile the legacy total or
establish a separate total wealth figure.

Doctrine: lines 1, 3, 5, and 6 hold: the existing authenticated control-plane
read leaves paid peer admission intact, preserves key-based authorization and
self-custody, and exposes measured categories with their limits.

### Pricing: stale means "fell back"

When the chain-aware engine cannot refresh its chain state (backend down or
not synced), prices fall back to the static table — which is what the node
really charges at that moment — while `raw_fee_rate` / `ema_fee_rate` in the
body still show the last cached values, if any. `Stale: 1` marks that
situation. `As-Of` is then the time of that last cache fetch, or the read time
if there has never been one. Cached state seeded from a snapshot at startup is
reported as already `cache_ttl` old, never as "now".

The same holds for a partial failure on a synced backend. When `estimate_fee`
fails for one or all confirmation targets, the engine keeps charging the last
value for those targets, and a cache refresh does not make that value any
newer. Each fee rate and the block height carry the time the chain really
answered for them. `As-Of` is the oldest of those times, and `Stale: 1` is set
once it is at or past `cache_ttl`. A block height that could not be fetched
(prices then use base halving sensitivity) counts as already `cache_ttl` old.

## Error responses

Only successful (`2xx`) responses carry the headers. A `401`, `403`, `4xx`
validation error or `5xx` backend error has neither header: there is no data
whose age could be stated. Clients must treat "no header" as "age unknown".

## Other routes

Only the six routes above. `/api/v1/status`, `/pricing/peers`, and every
other route do not send the headers; they may adopt them later.

## CORS

The headers are **not** added to `Access-Control-Expose-Headers`, and the CORS
layer is unchanged. The consumer, bitsov-app, reads these routes from
host-side Rust (the `src-tauri` broker, `reqwest` over loopback), where CORS
does not apply; a browser page would see the headers only if a later change
exposes them. Exposing them is a deliberate future decision, not an oversight.

## Compatibility (rc7)

Purely additive: no body, status code, route, auth or scope change. Clients
that ignore unknown headers (all rc7-era clients) are unaffected. A client
talking to a node that predates this change sees no header and must fall back
to "age unknown".

Note for the app side: the pre-implementation spec (bitsov-app F4) proposed
`BitSov-Data-As-Of` as ASCII digits (ms since epoch). The node sends RFC 3339
UTC instead; the app's header parser must accept that form.
The deviation is deliberate; see the reconciled spec,
[`specs/G-STALENESS-MARKER.md`](specs/G-STALENESS-MARKER.md).

## Changelog

The repository has no changelog file. This change (G-STALENESS-MARKER) is
recorded here and in the PR only; no release version is assigned by it.
