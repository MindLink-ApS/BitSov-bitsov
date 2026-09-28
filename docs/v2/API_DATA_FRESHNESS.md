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
