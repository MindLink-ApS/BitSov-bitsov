# Offline-tolerant startup (BOOT-2)

After the bounded LDK startup retry exhausts its chain-source budget, BitSov
starts its local services with `money_ready: false`. Identity derivation, storage
and pairing stay available. Configuration, key, storage and other non-connectivity
startup failures still fail immediately. No mock backend or substitute fee
estimate is used.

`GET /api/v1/status` advertises `offline_readiness_v1` and returns:

```json
{
  "money_ready": false,
  "readiness": {
    "money_ready": false,
    "state": "offline",
    "retry_attempt": 0,
    "retry_after_secs": 5,
    "events": [
      {"sequence": 1, "timestamp": 1790596800, "state": "offline", "money_ready": false}
    ]
  }
}
```

`retry_attempt` counts background startup rounds after the initial bounded
attempt. Each round uses the existing bounded real-fee retry/failover policy.
The delay between failed rounds doubles from 5 seconds to a 60-second ceiling.
`retry_after_secs` describes the scheduled delay, not a live countdown; it is
null while an attempt is running. One task owns retry and readiness monitoring.
Status reads never start work. The last 32 transitions are retained with
process-local monotonic sequence numbers; clients should reset their event
cursor after a process restart.

States are `offline`, `retrying`, `synchronizing`, `ready`, `failed` (a permanent
error during a background attempt; correct configuration and restart), and
`stopped`. Money becomes ready only after LDK's real fee barrier succeeds and
both wallets synchronize beyond their pre-start timestamp snapshots. Readiness
is revoked if LDK stops or its fee/wallet data becomes stale (two configured
LDK default update periods: 1,200 seconds for fees, 60 for the Lightning wallet,
160 for the on-chain wallet). The already-running LDK tasks continue syncing;
the supervisor does not start another backend. Readiness is polled once per
second. It is independent of available balance or channel liquidity.

Money routes return HTTP 503 with `code: "not_ready"` while unavailable. This
includes invoice issuance, pay/keysend, paid compose, channels, on-chain sends,
and liquidity/sponsor funding actions. Established free conversations can use a
prompt local quote; an unavailable quote never becomes a guessed free price.
Provider-level gates also protect internal callers. Wallet reads report unknown
while unready. Health/status avoid failed chain requests during offline startup.

The existing session maintenance loop reannounces Lightning details to connected
privileged peers after recovery. Identity and the wallet directory are reused.
Shutdown cancels retries and waits for backend persistence; cancellation of a
shutdown caller does not cancel the worker's cleanup.

Regression evidence includes a real LDK loopback Esplora fixture: fee requests
fail through exhaustion, fees recover before wallet synchronization, then both
wallets synchronize against mainnet genesis and invoices become available. The
startup log proves stable Lightning identity and one successful task startup.
API tests cover money refusal, local reads and pairing; lifecycle tests cover
backoff, concurrent status reads, and cancellation during shutdown.
