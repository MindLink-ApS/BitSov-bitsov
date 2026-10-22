# Starter hub (N-M7a PR-1, rc20)

This opt-in hub service requires embedded LDK on **signet** or **regtest**. Regtest is for tests. Mainnet, testnet, non-LDK backends, `allow_mainnet = true`, and `--home` / `--remote-unlock` are refused at startup. Existing configurations remain disabled. The [newcomer API and worker](starter-newcomer.md) are separately enabled on the newcomer.

```toml
[starter_hub]
enabled = true
capacity_sats = 100000
push_sats = 10000
funding_priority = "economy"
max_funding_fee_sats = 2000
max_opens_per_day = 20
max_concurrent_opens = 4
lifetime_budget_sats = 2000000
allow_mainnet = false
```

Issue a pending invite for the newcomer's mesh identity through the existing Admin invite API. Issuance updates the live transport whitelist, including an existing connection. The newcomer connects its Lightning peer to the hub and sends a signed `StarterRequest` over the privileged Noise connection. Amounts are always selected by the hub configuration. Grant and operation records precede dispatch. ONB5 and the starter worker compete for the same pending invite before either may open.

The daily allowance resets at UTC midnight. The lifetime budget does **not** reset: it charges the full channel capacity, including ready and operator-resolved grants. At the defaults, twenty 100,000-sat channels exhaust the lifetime budget even if issued on different days. Increasing that budget is an operator configuration change and restart; a daily reset or channel close does not replenish it.

## Resolve an uncertain grant

After ten minutes without an unambiguous channel match, an operation is uncertain. A timeout, missing channel, or missing event never proves non-dispatch. Do not delete its rows or reduce its counters manually.

Inspect the hub's channel list and funding transactions. If the outcome remains unknown, the Admin-only endpoint below accepts the possible loss and releases the in-flight slot:

```http
POST /api/v1/onboarding/starter-grants/{request_id}/resolve
Authorization: Bearer <operator-admin-token>
Content-Type: application/json

{"resolution":"charge"}
```

The grant becomes `resolved`. Its capital charge, original admission-day charge and one-per-node/LN-key reservation remain. Repeating the resolution is safe. The endpoint has no refund option. A live dispatcher's proven `PaymentNotDispatched` result can release money. An expired or revoked invite also releases an admission when the transaction proves no dispatch operation exists. A later channel observation still reconciles the grant to ready.

## Funded channel that never becomes ready

A channel that still matches the grant but never reports durable readiness remains
`opening` and holds one concurrency slot indefinitely. The ten-minute uncertain
rule does **not** apply while that channel is listed, even if its peer is offline.
At the default limit, four such channels block new admissions with `hub_busy`.
Calling `resolve` at this point returns a conflict; it cannot release the slot.

1. Inspect `GET /api/v1/payments/channels` and the funding transaction. Confirm the
   grant's channel ID, peer and capacity. Check confirmations and peer connectivity;
   allow normal recovery if the newcomer is expected to return.
2. If the operator decides to abandon the channel, use the existing close API with
   an operator token carrying Spend scope:

   ```http
   POST /api/v1/payments/close-channel
   Authorization: Bearer <operator-spend-token>
   Content-Type: application/json

   {"channel_id":"<listed channel_id or user_channel_id>","force":true}
   ```

   Force-close broadcasts the latest commitment when available; it incurs on-chain
   fees and funds may remain timelocked. It is not a refund of the starter grant.
   The close API requires the money backend to be ready.
3. Confirm the channel disappears from the hub's channel list. A `closing`
   response alone is insufficient. Keep the starter worker enabled and wait for
   its next 15-second reconciliation tick. Once the original open operation is at
   least ten minutes old **and** no channel matches, it becomes `uncertain`.
4. Call the Admin `resolve` endpoint above with `{"resolution":"charge"}`. Verify
   `state: "resolved"` and `inflight_released: true`. This releases only the slot:
   capital, admission-day usage and identity reservations remain charged, even
   when closing funds later return. The worker never reopens this grant. A later
   durable ready observation can still reconcile it to `ready`.

Recovery scans opening grants periodically and after startup, including operations already recorded as opened; it reads durable readiness rather than waiting for a replayed `ChannelReady` event. Ordinary pre-dispatch errors get at most three attempts. A construction-time fee-cap refusal ends the grant immediately. Only the newest refused grant per requester is retained; a new admission replaces it. Rate-limited responses are not persisted and do not extend the ten-minute per-node admission throttle. Retained refusal UUIDs replay their status; older pruned UUIDs are evaluated again. Retryable refusals require a fresh request UUID.

## Privacy and rollback

Starter tables retain the LN key for uniqueness and recovery, but no IP/socket address or LN alias. Before dispatch the hub removes any previously persisted peer address and durably suppresses future `PeerInfo` persistence for that key. The newcomer must reconnect to the hub. Identity-bearing LDK connection/channel diagnostic records for marked starter peers are below INFO; ordinary peer and node lifecycle diagnostics retain their original levels; the hub's starter logs contain mesh id/request id and fixed outcomes only.

Set `enabled = false` and restart to stop the worker and capability advertisement. Existing channels remain intact. The Admin charged-resolution endpoint remains available for previously created uncertain grants.

PR-2 implements C3 with durable negotiated initial-push evidence and F4 with bounded, persisted retry successors. Timeouts reuse the same UUID; only an explicit retryable refusal permits a successor UUID. See [newcomer operations](starter-newcomer.md) for bounds, backoff and status. Mainnet still requires an explicit policy decision and idle reclaim.

## Confirmation policy and before-mainnet checklist

Starter channels are not configured as zero-confirmation channels.
`trust_no_reserve` affects the anchor-reserve policy only; the newcomer still
requires LDK's inbound funding confirmation depth and channel-ready checks.

The newcomer's `ready` request state is terminal. Once verified, it is not
re-checked for confirmation depth, a later deep reorg, or channel closure.
Before mainnet GO, decide and implement ongoing readiness/reorg/closure handling
and idle reclaim; a historical `ready` request must not be treated as proof of
current spendable channel liquidity. Mainnet remains disabled.


## App discovery and owner activity

On the **newcomer**, optionally configure an operator display name:

```toml
[starter]
enabled = true
hub_node_id = "<64-hex hub mesh identity>"
hub_alias = "MindLink signet hub"
```

This alias is display-only, not the hub's LN alias, address or identity. The
owner/paired `read` GET `/api/v1/onboarding/starter-channel` returns 200 before
any request, with `state: "not_requested"`, `hub_configured`, and `hub_alias`
when configured. Existing request responses include these discovery fields too.
`hub_configured` checks local enabled hub configuration, not reachability,
funds, invites or readiness. The capability advertisement is unchanged. These
fields are not published on unauthenticated health or discovery surfaces.

A paired `receive` POST accepts only `request_id`. Cost, fee, amount and push
fields are rejected before dispatch: the newcomer cannot spend through this
flow. Retrying the same UUID is idempotent; it does not create a second grant
or change the requesting device attribution. No additional owner approval kind
is needed for this receive-only request.

The newcomer's configured `api.audit_log_path` contains owner activity events
`starter.requested`, `starter.ready` and `starter.refused`. Each carries the
requesting `paired_device_id`, operation UUID, root request UUID, state and
terminal refusal reason. Retries and adopted operations retain the original
paired device after restart; historical requests predating attribution use
`unknown`. A requested entry is an intent recorded before persistence and may
remain if the process stops before creating the request. Audit write failure
blocks new dispatch until logging succeeds. Keep the audit file across restarts.
For a local console listing (using the configured path):

```sh
jq -c 'select(.event | startswith("starter.")) | {timestamp,event,actor,detail}' /path/to/audit.jsonl
```

These are private owner activity records; do not publish the log. No database
migration is required.

Conflicts before operation creation are separate `starter.request_conflict`
events, not terminal hub refusals; that UUID can be accepted later. Attribution
binds to the first device that requested the UUID. If authenticated adoption
revives a refused UUID, a new `starter.requested` transition allows its next
terminal outcome to be logged. Reconciliation repairs missing terminal events
for earlier operations even after a newer request becomes current. Startup
separates a crash-truncated journal tail before appending new records.
