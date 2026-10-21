# Owner funding fees (#190)

`POST /api/v1/payments/open-channel` accepts `funding_priority`:

| Choice | Pinned LDK estimator target | Blocks | Approximate confirmation time |
| --- | --- | ---: | ---: |
| `economy` | `ChannelCloseMinimum` | 144 | 24 hours |
| `normal` (default) | `ChannelFunding` | 12 | 2 hours |
| `fast` | `OnchainPayment` | 6 | 1 hour |

These are the nearest existing, unadjusted LDK Node 0.7 estimator targets. The
local vendor extension selects their cached rates; it does not change commitment,
close, sweep, or payment fees. Fast is a six-block target, **not next-block**.
Rates can be identical on a quiet mempool. Bitcoin block times vary, mempool
conditions change, and the peer's required funding depth adds time before
`channel_ready`. No confirmation deadline is promised.

Use the same owner-authenticated endpoint to preview without opening a channel:

```json
{
  "peer_pubkey": "<compressed Lightning public key>",
  "peer_addr": "<IP address>:9735",
  "amount_sats": 100000,
  "funding_priority": "fast",
  "max_funding_fee_sats": 2000,
  "dry_run": true
}
```

The read-only response has `status: "preview"` and, for example:

```json
{
  "funding_fee": {
    "priority": "fast",
    "confirmation_target_blocks": 6,
    "expected_confirmation_minutes": 60,
    "estimated_fee_rate_sat_per_vb": 5.016,
    "max_funding_fee_sats": 2000
  }
}
```

The rate above is illustrative, not a live quote. Preview requires the usual
money readiness and owner spend authorization; it does not connect the peer,
reserve coins, sign, or broadcast. Set `dry_run: false` (or omit it) to open.
Opening selects the **current cached estimate**, so compare the cap with the amount you are
willing to pay. The preview is not a quote token or a reservation. The ordinary
open response includes `user_channel_id`, `channel_id`, `funding_txo`,
`funding_txid`, and visibility `status`, and
adds `funding_fee` with the estimate actually selected for an explicit priority
or cap. Legacy opens without these options leave `funding_fee` unset. An
`opening` or `pending_visibility` response is not evidence of confirmation.

The chosen rate and optional cap are saved before channel negotiation. LDK's
asynchronous funding event uses that saved policy. The policy survives restart
and governs any subsequent construction attempt; a cache refresh cannot increase
the selected rate. Missing or corrupt policy
storage fails closed. A recorded refusal is terminal for that channel ID, even if the wallet later recovers or a construction attempt repeats. There is no automatic repricing or funding fee bump.
The displayed rate is an estimate used by the builder, not a promise of exact
final sat/vB: transaction rounding and dust change can affect the final fee.

`max_funding_fee_sats` is optional and must be 1–2,100,000,000,000,000 satoshis.
It limits the **whole funding transaction fee**, including change folded into
fees. The unsigned PSBT's absolute fee is checked before signing, reservation,
or broadcast. A cap refusal terminates the unfunded opening and returns
`not_dispatched` with the construction failure reason when observed by the API.
A timeout, storage failure, or lost response remains uncertain: inspect the
channel/events before retrying. There is no automatic retry at a larger cap.

`fee_rate_sat_per_vb` remains refused by the LDK provider (#101), including when
combined with a priority, cap, or preview. Arbitrary block targets, unknown
priorities, and unknown fields are refused. Non-LDK providers that have not
implemented these controls refuse explicit priorities/caps/previews with
`not_dispatched`; they do not silently ignore them. Legacy requests without new
options keep their existing provider path, including LDK's cached/fallback
`ChannelFunding` rate with no new quote-freshness requirement.

Explicit priorities, caps, and previews require a real cached LDK estimate.
Its maximum age is **twice the configured fee refresh interval, with a minimum
of 900 seconds**. The default 600-second interval permits estimates up to 1,200
seconds old; a 1,800-second interval permits 3,600 seconds, and a 3,600-second
interval permits 7,200 seconds. An older or missing estimate refuses the request
before peer connection. Wait for a successful scheduled refresh before retrying;
there is no owner API for manually refreshing fees. LDK's chain-source-specific
conversion/floor behavior remains unchanged. In particular, empty Esplora fee
estimates on regtest/signet retain the legacy funding fallback, but cannot be
used for an explicit quote or capped opening.

## Initial balance push

The same owner API accepts optional `push_sats` to give the counterparty an
initial balance from the channel funding. Omitted or `null` means no push and
preserves existing behavior. For example:

```json
{
  "peer_pubkey": "<compressed Lightning public key>",
  "peer_addr": "<IP address>:9735",
  "amount_sats": 100000,
  "push_sats": 10000,
  "funding_priority": "economy",
  "max_funding_fee_sats": 2000
}
```

`push_sats` must be at most `amount_sats / 2` (rounded down). Larger values
return HTTP 400 before opening or previewing; amounts that cannot be converted
safely to millisatoshis also return 400. The push is a gift to the peer, not an
additional funding fee or additional channel capacity. `0` is an explicit push
request, and unsupported backends refuse it as well as positive pushes.

Push uses the funding-policy path, with normal priority when no priority is
specified, and requires a fresh cached LDK fee estimate. It can be combined
with the absolute funding fee cap, but not with `fee_rate_sat_per_vb` (HTTP 400).
`dry_run` validates the push and only previews the funding fee; it never opens
or transfers a balance and does not guarantee that the peer will accept.
Backends that cannot enforce a push return HTTP 400 `not_dispatched` when
opening; they never silently discard it.

Authorization is unchanged: the endpoint requires unpaired Spend authority.
Full owner tokens include this scope; Admin alone does not substitute for it.
A paired client's budget-scoped spend grant cannot open a channel or push funds.
An explicit push does not enable any automatic onboarding opens.

## Why there is no funding bump command

Verified against the pinned vendored LDK Node 0.7.0 / lightning 0.2.2 source and
[LDK Node's public API](https://docs.rs/ldk-node/0.7.0/ldk_node/struct.Node.html).
`payment/onchain.rs::OnchainPayment` exposes sending/draining and address
creation, but no owner-directed CPFP of a specified funding txid/change outpoint.
`events::bump_transaction::BumpTransactionEventHandler` handles LDK-generated
commitment/HTLC bump events. Anchor outputs belong to commitment transactions;
they are not wallet-owned funding outputs that this API can arbitrarily spend.
Calling the ordinary send API cannot ensure that the funding change is selected,
that the package fee is correct, or that a hard absolute bump cap is respected.

A supported implementation still needs a funding-parent lookup with reliable
confirmation/conflict state, wallet-owned unspent change selection, ancestor
fee/weight accounting, child construction and signing with an absolute fee cap,
reservation integration, and unambiguous broadcast/restart handling. None is
exposed as a funding-bump operation in this pinned LDK API. No CPFP/RBF command
was added, and the funding cap above must not be mistaken for a bump cap.

Tests cover HTTP preview/owner/refusal behavior, target/rate mapping, stale and
missing estimates, durable policy after restart, missing/corrupt policy refusal,
and the actual BDK unsigned fee-cap boundary. They use disposable wallets and
synthetic funds, without starting a node or opening sockets.

## Channel identifiers and closing

For LDK, successful `POST /api/v1/payments/open-channel` (HTTP 200) and
`GET /api/v1/payments/channels` use the same identifiers:

| Field | Encoding and meaning |
| --- | --- |
| `user_channel_id` | Stable LDK-local u128, as a plain decimal **string** (e.g. `"88160000000000000000000000000000000001"`). Never convert to a JavaScript number. |
| `channel_id` | 32-byte Lightning channel ID, as 64 hex characters. It may change during negotiation before funding is assigned. |
| `funding_txo` | Funding outpoint, `"<64-character txid>:<output index>"`; null before assignment. |
| `funding_txid` | Open response only: the funding transaction's 64-character hex ID. |
| `short_channel_id` | List response only: routing SCID, or null before assignment; **not** a close identifier. |

Previously LDK returned `UserChannelId(n)` in `channel_id`. Clients should now
store `user_channel_id` as the stable identifier. `channel_id` for CLN remains
its hex channel ID; LND retains its native `chan_id`. Other providers expose
null for `user_channel_id` and for unavailable `funding_txo` values.

Close an LDK channel using either listed identifier in the request's
`channel_id` field:

```json
{"channel_id":"88160000000000000000000000000000000001","force":false}
```

Send this to `POST /api/v1/payments/close-channel`. The 64-character hex
`channel_id` also works; legacy `UserChannelId(n)` values remain accepted.
Owner Spend authorization and close safety checks are unchanged.

Both `opening` and `pending_visibility` mean the open has been dispatched;
do not retry either response to wait for readiness. Poll the channel list.
A transport failure or uncertain backend error still requires inspecting
channels/events before retrying, unless the open carried an `operation_id`
(below).

## Idempotent opens with `operation_id` (#331)

Nodes advertising `channel_open_operations_v1` in `/api/v1/status`
`api_capabilities` accept an optional `operation_id` on
`POST /api/v1/payments/open-channel`: a client-generated UUIDv4, as for message
compose. Generate it before the first request and keep it through timeouts,
502s and restarts.

```json
{
  "peer_pubkey": "<compressed Lightning public key>",
  "peer_addr": "<IP address>:9735",
  "amount_sats": 100000,
  "operation_id": "6f1c9a52-6c8e-4c1e-9f3b-2d6a0e7b5c41"
}
```

The node records the id and a digest of the request parameters (`peer_pubkey`,
`peer_addr`, `amount_sats`, `push_sats`, `announce`, `funding_priority`,
`max_funding_fee_sats`, `fee_rate_sat_per_vb`) in `channel_open_operations`
(migration 030, SQLite and PostgreSQL; the request and response are encrypted
at rest) **before** dispatch. A request carrying a recorded id never opens again:

| Recorded state | Same id, same parameters |
| --- | --- |
| `opened` | HTTP 200 with the original open response, plus `operation_id` and `replayed: true`. |
| `uncertain` (the first attempt returned a timeout, connection or backend error) | HTTP 202 `status: "outcome_uncertain"`, `last_error`, and `peer_channels` (this peer's current channels, or null if Lightning cannot list them). Inspect them; to try again, use a **new** `operation_id`. |
| `pending` (dispatch in flight, or at most ten minutes old) | HTTP 202 `status: "pending"` with the same fields. |
| `pending` older than ten minutes, with no in-process open running | Inspect the node's channels: exactly one channel to the requested peer with the requested capacity records `opened` and returns HTTP 200; zero or multiple matches, or an unavailable channel list, records `uncertain` and returns HTTP 202. Never dispatches again. |

Dispatch and outcome recording for an operation run in a background task that
survives an HTTP client disconnect. A node crash or failed outcome write can
still leave a `pending` row. Retrying the same id after ten minutes reconciles
that row using the existing timestamps and result columns; no new migration is
required. An open still running in this process is never reconciled, regardless
of age.

A recovered success includes `recovered: true` and the observed channel IDs and
funding outpoint. Its `pending_visibility` status does not claim transaction
visibility or confirmation; its original fee quote is unavailable. Peer and
capacity matching cannot prove that the observed channel was created by this
operation, so inspect it before taking further action. An uncertain recovery
includes an "inspect GET /payments/channels" hint (the full route is
`GET /api/v1/payments/channels`). Neither an uncertain record nor an absent
channel permits automatic re-dispatch. A settled record keeps its outcome on
later retries even if the channel list changes.

The same id with any different parameter returns `409 operation_mismatch`
before dispatch. A proven non-dispatch (`400 not_dispatched`, or `503 not_ready`
from the backend) removes the record, so the same id may be retried. For the
pinned LDK open path, stopped-node, insufficient-funds, peer-connection,
invalid-socket-address, channel-capacity-limit, and channel-creation validation
refusals are proven to occur before LDK accepts the open. Persistence failures
remain uncertain because peer persistence can fail after creation. These
classifications apply at the open-call boundary; a later funding timeout or
unknown backend error does not become retry-safe. A replay
does not require `money_ready`. `operation_id` cannot be combined with
`dry_run` (`400 not_dispatched`); an invalid id is HTTP 400. The first
successful response also includes `operation_id`.

Without `operation_id`, behaviour is unchanged: nothing is recorded and every
request may open a channel.

Owner `GET /api/v1/status` reports `network` from the configured Lightning
network, matching `/api/v1/payments/funding-address` (for example `"signet"`).
It is null only when no network is available in that backend's configuration.
