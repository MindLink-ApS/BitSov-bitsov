# G-STALENESS-MARKER — per-response "as of" marker on the pinned read routes

**Type:** genome (BitSov-bitsov) spec, reconciled with the implementation in
PR #78 (`factory/data-staleness-headers`). The authoritative description of
the shipped behaviour is [`../API_DATA_FRESHNESS.md`](../API_DATA_FRESHNESS.md);
this file records the problem, the original proposal and where the build
deliberately differs.
**Raised by:** bitsov-app F4 broker staleness (app PR #36). App side:
`src-tauri/src/jarvis/broker/freshness.rs`, `docs/ASSISTANT_LOCAL_BROKER.md`
§ Freshness.
**App pin at time of writing:** `v0.3.0-rc7` (`958e399`). The behaviour described
here landed on `main` in #78 and ships in the prepared `v0.3.0-rc8` cut; no tag
or app re-pin is performed by this spec's original PR.

## Problem

The app can say how long ago *it* read the node (host monotonic stamp per
response, fresh / stale at 60 s / unknown). It cannot say how old the node's
*figures* are. On rc7 none of the five pinned GET routes carries a time that
means "this data was current at T":

| Route | rc7 body | Time-like fields | Why they do not answer "as of" |
|---|---|---|---|
| `GET /api/v1/payments/balance` | `BalanceResponse {balance_msat}` | none | — |
| `GET /api/v1/payments/channels` | `[ChannelResponse]` | none | — |
| `GET /api/v1/health` | `PublicHealthResponse` | `block_height: Option<u64>`, `uptime_secs` | height is not a time; uptime is process age |
| `GET /api/v1/messages` | `[MessageResponse]` | `timestamp` (ms, per message) | send time of each message; an idle mailbox is old and current |
| `GET /api/v1/pricing` | `OwnPricingResponse` | `block_height: u64` (0 if chain unknown) | height, not a time |

A node answering from a stale cache (LDK wallet not synced since the chain
backend dropped, pricing computed against an old tip) answers 200 with the
cached figure, and the app shows it as *fresh*.

## Shape (as built)

A response **header**, not a body field: `/payments/channels` and `/messages`
return bare JSON arrays, so a body field would change their shape.

```
BitSov-Data-As-Of: 2026-09-27T08:20:00Z   (RFC 3339, UTC "Z", whole seconds)
BitSov-Data-Stale: 1                      (optional; present only when the node knows)
```

- `BitSov-Data-As-Of` — the oldest "last known current" time among the
  sources the handler used for this response. Node clock, clamped to the
  node's "now"; fractions truncated. Exactly 20 ASCII characters.
- `BitSov-Data-Stale: 1` — the node's own judgement that the data is past its
  freshness bound. Absent means "not known stale", not "fresh". No other value.
- Only `2xx` responses carry the headers; errors carry neither.

### Deliberate deviation from the original proposal

The first draft of this spec (written app-side during F4) proposed
`BitSov-Data-As-Of: <u64 ms since Unix epoch>`, ASCII digits only. The node
**deliberately** sends RFC 3339 UTC whole seconds instead, as the genome
ticket required: it is self-describing on the wire and in logs, unambiguous
about the unit and zone, and sub-second precision carries no meaning for data
whose freshness bounds are 60 s to 10 min. Consequence for the app: its parser
must accept RFC 3339 (primary); accepting digit ms as well is harmless
tolerance, but no node sends it.

## Per route (as built)

| Route | `BitSov-Data-As-Of` | `BitSov-Data-Stale: 1` when |
|---|---|---|
| `/payments/balance`, `/payments/channels` | LDK: older of last Lightning and last on-chain wallet sync; absent until both have synced once. LND/mock (LNbits not selectable — #99/#104): time just before the backend read | LDK only: sync ≥ 10 min old (`WALLET_SYNC_STALE_AFTER`), or never synced |
| `/health` | time the chain backend was queried for `block_height`; absent when `block_height` is null | never |
| `/messages` | time the local message store was read ("read just now", present for uniformity) | never |
| `/pricing` | chain-aware: the oldest real chain fetch among the served values (per-target fee rates + block height); values reused after a failed fetch keep their old time, seeded values count as `cache_ttl` old; static: time of the read | chain-aware only: that oldest fetch at/past `cache_ttl` (default 60 s), or no cache, i.e. prices fell back to the static table or are built on reused inputs |

Differences from the first draft: pricing's As-Of is the chain *fetch* time
(the draft said "time of the block height"); balance/channels on a never-synced
LDK wallet omit As-Of and send `Stale: 1`.

## Backward compatibility with rc7

- Header-only; no body, status code, route, auth or scope change.
- rc7-era clients ignore unknown headers.
- A client talking to an rc7 node sees no header and keeps today's
  behaviour: host stamp only, node data age "unknown".
- CORS unchanged; the headers are not exposed to browsers because the app
  reads these routes from host-side Rust over loopback (see
  `API_DATA_FRESHNESS.md` § CORS).

## How the app consumes it

1. The broker keeps the two headers on the raw read: `BitSov-Data-As-Of`
   parsed as RFC 3339 (primary; offsets normalised to UTC), digit ms tolerated;
   anything else dropped as absent. `BitSov-Data-Stale` honoured only when `1`.
2. Node data time = As-Of, with the existing clamp: more than 120 s ahead of
   the host clock → clamped and flagged as clock skew.
3. Precedence for the label: `Stale: 1` → stale; else node As-Of age vs the
   stale bound; else app-read age; else "Freshness unknown".
4. Optionally a stale-marked read becomes `ReadFault::Stale`. Product decision.
5. Inert until the app's pinned node includes this change.

## Acceptance (genome side)

- Each of the five routes sends `BitSov-Data-As-Of` on 200 (except the
  documented absences), with handler tests. Done in #78.
- `BitSov-Data-Stale: 1` covered by tests forcing a stale sync / expired
  pricing cache. Done in #78.
- Tag and app pin bump follow separately (not in #78), via the usual
  `scripts/fetch-node-sidecar.sh` + CS-1/CS-2 smoke path.

## Non-goals

Push/subscribe or polling; signing the header; changing any body; spend,
invoice or restore routes; CORS exposure.
