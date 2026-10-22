# Newcomer starter channel (N-M7a PR-2)

This default-off feature asks the configured signet hub to fund one private
starter channel. It does not spend or open a channel on the newcomer. Regtest is
supported for tests; mainnet, testnet, non-LDK backends and `allow_mainnet = true`
are refused at startup. The hub operator must first issue an invite for this
node's mesh identity, as described in [starter-hub.md](starter-hub.md).

Configure embedded LDK, the hub in `[[peers]]`, and the same hub's LN identity and
address as the selected `[lightning.liquidity]` provider with
`enabled = true` and `trust_no_reserve = true`. Then add:

```toml
[starter]
enabled = true
hub_node_id = "<64-hex hub mesh identity>"
hub_alias = "Signet starter" # optional operator display name
allow_mainnet = false
```

The authenticated status endpoint advertises `starter_channel_request_v1` while
enabled. A verified paired session with `receive` scope may call:

```http
POST /api/v1/onboarding/starter-channel
Content-Type: application/json
Authorization: Bearer <paired-receive-token>

{"request_id":"<UUIDv4 generated once by the app>"}
```

An unpaired token, including Admin or loopback authority, is refused. GET on the
same path returns the current request, or 200 `not_requested` before the first
request with `hub_configured` and optional `hub_alias`; GET with `/{request_id}` follows that
owner request through automatic retries. Both GETs require `read` scope. POST
returns 202 on creation and 200 on replay. A different live owner request gets
409, including its ID. Changing the configured hub/key/network causes a replay
409 `operation_mismatch`.

Responses expose `requested`, `opening`, `ready` or `refused`, `detail`, refusal
`reason`, retry timing, hub identities, amounts, channel identifiers and
`verified`. `operation_id` identifies the current hub attempt; `request_id`
remains the owner's polled ID. `original_request_id` links automatic successors
to their original owner request, including adopted hub grants. A pending
adoption target is persisted separately in `detail` as `adopt:<UUID>` so crash
recovery cannot replace the local lineage root.

## Delivery and recovery

Timeouts and lost responses resend **the same operation UUID**, which is also
the hub's channel-open operation ID. Backoff is 15, 30, 60, 120, then 300 seconds,
with eight sends per mesh connection. Offline time does not consume sends.
After exhaustion, `detail` reports `delivery_retry_exhausted` (or
`hub_silent_24h`). A hub reconnect or explicit POST replay rearms delivery with
the same operation ID; GET is read-only. Local channel reconciliation continues
every 15 seconds even after delivery exhaustion. Silence never marks a request
refused and never permits another open.

Only an authenticated retryable hub refusal permits a new operation UUID, because
PR-1 stores refusals as terminal. Successor creation is transactional, with at
most three successors per owner request. The minimum delays are 10, 20 and 40
minutes, also respecting a later hub `retry_after_unix`. The limit and lineage
survive restart. Exhaustion is surfaced as `auto_retry_exhausted`; the owner may
explicitly start a fresh request after a proven refusal. Non-retryable refusals
never automatically create successors. `already_served` adopts the identified
original grant instead, including when its old local record was refused. A new
adopted UUID consumes one of the same three successor slots; revisiting a known
UUID preserves its lineage and cannot replenish the budget. A target belonging
to another local lineage is not adopted.

## Push evidence

`ready` requires the local channel to be inbound, private, active and ready,
with the configured counterparty, matching capacity and any stated channel or
funding identifiers. Capacity is capped at 200,000 sats. LDK's negotiated initial
push is persisted with the channel before it can be used, and must cover the
hub's promised push. Spending later does not erase this evidence. A hub `ready`
frame alone is insufficient. `trust_no_reserve` relaxes the anchor-reserve
policy only; it does not configure zero-confirmation trust. Inbound funding
must reach LDK's required confirmation depth and channel-ready checks.
Advertised balance alone is not spendable liquidity.

Channels written by older versions have unknown initial-push evidence and fail
closed (`verify_mismatch`). This patch adds optional, backward-readable LDK TLV
fields; it adds no SQL migration. The existing migration 031 table holds all
newcomer requests, attempts, retry lineage and verification timestamps.

Set `[starter] enabled = false` and restart to stop delivery. Existing channel
balances remain available, and persisted request status remains readable.

## Before mainnet

`ready` is terminal: the newcomer worker stops reconciling that request and does
not re-check confirmation depth, a later deep reorg, or channel closure. The
record reports successful starter verification at `verified_at`, not continuing
channel availability. Before any mainnet GO, decide and implement ongoing
readiness/reorg/closure handling together with the idle-reclaim policy. Mainnet
remains disabled pending those decisions and validation.
