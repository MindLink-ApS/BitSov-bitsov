# Starter hub (N-M7a PR-1, rc20)

This opt-in hub service requires embedded LDK on **signet** or **regtest**. Regtest is for tests. Mainnet, testnet, non-LDK backends, `allow_mainnet = true`, and `--home` / `--remote-unlock` are refused at startup. Existing configurations remain disabled. PR-2 supplies the newcomer app API and worker.

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

Recovery scans opening grants periodically and after startup, including operations already recorded as opened; it reads durable readiness rather than waiting for a replayed `ChannelReady` event. Ordinary pre-dispatch errors get at most three attempts. A construction-time fee-cap refusal ends the grant immediately. Refused grants require a new request UUID; retry times respect the ten-minute per-node admission throttle.

## Privacy and rollback

Starter tables retain the LN key for uniqueness and recovery, but no IP/socket address or LN alias. Before dispatch the hub removes any previously persisted peer address and durably suppresses future `PeerInfo` persistence for that key. The newcomer must reconnect to the hub. Identity-bearing LDK connection/channel diagnostic records are below INFO; the hub's starter logs contain mesh id/request id and fixed outcomes only.

Set `enabled = false` and restart to stop the worker and capability advertisement. Existing channels remain intact. The Admin charged-resolution endpoint remains available for previously created uncertain grants.

PR-2 TODOs: Codex C3 requires durable initial-push evidence or spending exclusion before newcomer verification; Fool F4 requires automatic retries with fresh UUIDs after retryable refusals. Neither is implemented by this hub PR. Mainnet still requires an explicit policy decision and idle reclaim.
