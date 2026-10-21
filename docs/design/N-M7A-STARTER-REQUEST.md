# N-M7a — Newcomer starter-channel request + status API (Option A, signet)

Design note, docs only. Source read at `origin/main` `e8ed587` (v0.3.0-rc19 prep). Paths are under `crates/` unless stated. No code changed.

**Goal (M7).** A brand-new user gets a hub-funded starter channel from inside the app, with no command line, so two users on their own nodes can message, call and pay each other from iPhone and Mac.

**Scope.** One owner-requested starter channel per node, funded by the hub from its own wallet under Option A / T4a (`docs/DESIGN-REASONING.md` T4a). Signet only. Implementable in two PRs (§11).

## 1. Why rc18/rc19 has no app-callable path

| Path | Why it does not work from the app | Where |
|---|---|---|
| `POST /invites`, `POST /invites/accept` | `ScopedAuth<Admin>`; Admin is never grantable to a pairing | `konsensus-api/src/handlers/invites.rs:279`, `:450`; `docs/security/pairing.md` §Scopes |
| `POST /onboarding/start` `tier: "light"` | Needs Admin, and only writes `OnboardingStateRecord`; nothing is sent to anyone | `handlers/onboarding.rs:162-185` |
| ONB5 auto-channel worker | Opens with no push. It also passes `Some(fee_rate)` to `open_channel` (`onboarding/auto_channel.rs:372-378`), which LDK refuses before dispatch (`konsensus-lightning/src/ldk.rs:3190-3197`), so on an LDK hub ONB5 never opens at all | as cited |
| `POST /payments/open-channel` with `push_sats` | Spends the **executing** node's own funds; `ScopedAuth<Spend>` with unpaired authority; paired budget grants cannot open or push | `handlers/payments.rs:991-1075`; `docs/UPGRADING.md:115-121` |
| Status | No request object exists, so there is no status to poll | — |

`docs/UPGRADING.md:119-120`: "No automatic onboarding opens are enabled." This design keeps that sentence true: every open is an explicit owner request admitted by an explicitly enabled hub policy (§9).

## 2. Roles

| Role | Who | Does | Never does |
|---|---|---|---|
| **Newcomer node** | The new user's own node (home box, Pi, Umbrel, owner VM) | Accepts the owner's request from the paired app, persists it, signs it with its LN key, sends it to its configured hub, verifies the resulting channel locally, reports status | Spends, opens a channel, changes config, or contacts any service other than its configured hub |
| **Hub node** | The dedicated non-lockable MindLink signet hub (T4a) | Applies admission policy, opens a private 0-conf anchor channel to the newcomer with a fixed push from its **own** wallet, reports status | Lends, records a balance owed, issues ecash, or opens without a persisted admitted request |
| **App** | Paired Mac / iPhone app | Generates a UUIDv4 `request_id` once, POSTs, polls GET, shows 4 states | Holds Admin or Spend for this flow |

Preconditions on the newcomer (written by the app's config template, Option A A1; checked at request time):
`[lightning.liquidity] enabled = true`, `selected_provider = <hub LN pubkey>` with `trust_no_reserve = true` (N1, #326), the hub in `[[peers]]` (so it is whitelisted and dialled), and `[starter] enabled = true, hub_node_id = <hub mesh id>`.

## 3. Message flow and channel choice

**Channel: the existing Noise_XX mesh transport session, as two new control frames.** Not the E2EE Double Ratchet message path, because:

1. Every UKM message must be paid (P2, `konsensus-core/src/gate.rs`). The newcomer has 0 sats; requiring a paid message to ask for the first sats is a deadlock.
2. X3DH/ratchet setup from a non-privileged peer is refused before payment (`konsensus-node/src/session_handler.rs:105-135`, `SessionBeforePayment`).
3. The request is protocol metadata between two nodes, not user content. The Noise session already authenticates both mesh node ids and encrypts the frame; the same reasoning is why `Frame::LightningInfo` travels there (`konsensus-message/src/wire.rs:844`, `session_handler.rs:437-469`).
4. LN custom messages were rejected: they bind only the LN key, need new LDK plumbing, and would put a second request path beside the mesh.

New frames (append to `Frame`, `konsensus-message/src/wire.rs:686`; JSON name-tagged, so existing encodings do not shift):

```rust
StarterRequest {
    v: u8,                 // 1
    request_id: Uuid,      // UUIDv4 from the app; idempotency key end to end
    network: String,       // "signet" (regtest in tests)
    ln_pubkey: String,     // newcomer LN node id, 33-byte hex
    ln_sig: String,        // LN node signature (zbase32, ldk-node sign_message) over CANON below
},
StarterStatus {
    request_id: Uuid,
    state: String,         // "received" | "opening" | "ready" | "refused"
    reason: Option<String>,        // refusal code, §6.3
    retry_after_unix: Option<u64>,
    capacity_sats: Option<u64>,
    push_sats: Option<u64>,
    channel_id: Option<String>,
    funding_txid: Option<String>,
},
```

`CANON = "bitsov-starter-v1\n{network}\n{hub_mesh_id}\n{newcomer_mesh_id}\n{request_id}\n{ln_pubkey}"`. It binds the LN key to the Noise-authenticated mesh id, so nobody can make the hub fund a third party's LN node and "one per LN key" is meaningful. New trait methods `LightningProvider::sign_message` / `verify_message` wrap `vendor/ldk-node/src/lib.rs:2056`, `:2062`; other backends return `PaymentNotDispatched`.

The hub advertises `Capability::Custom("starter_hub_v1")` in Hello/HelloAck only while `[starter_hub] enabled` (`konsensus-node/src/node.rs:736`).

```
App                    Newcomer node                         Hub node
 | POST starter-channel  |                                       |
 |  {request_id}         | checks §8 + preconditions             |
 |                       | persist row: requested                |
 | 202 requested  <------|                                       |
 |                       | LN connect(hub, persist=true)         |
 |                       |== Noise: StarterRequest ============> | verify sig, network, policy (§6)
 |                       |                                       | persist grant: admitted
 |                       | <========== StarterStatus received == |
 |                       |                                       | write channel_open_operations row (#331)
 |                       |                                       | open_channel_with_funding(push)
 |                       | <========== StarterStatus opening === | (channel_id, funding_txid)
 |                       | LDK: inbound 0-conf anchor channel    |
 |                       |   from selected provider, waiver ok   |
 |                       | <========== StarterStatus ready ===== | on ChannelReady
 |                       | local verification (§7) -> ready      |
 | GET -> ready <--------|                                       |
```

Resending `StarterRequest` with the same `request_id` is also the status query: the hub answers from its persisted row and never repeats work. The newcomer resends on every (re)connect to the hub while non-terminal, with backoff 15 s → 30 → 60 → 120 → 300 s (capped).

The newcomer's LN connection to the hub is opened by the starter worker (new `LightningProvider::connect_peer(pubkey, addr, persist)`; address from the selected provider entry). The hub opens over that connection: `connect_peer_if_necessary` short-circuits when connected (`vendor/ldk-node/src/connection.rs:40-48`), and the hub passes the address from `list_peers()` (`PeerDetails.address`). No NAT traversal, no vendor patch.

## 4. Newcomer API

Capability: `starter_channel_request_v1` in `/api/v1/status` `api_capabilities` (`handlers/health.rs:309`), only while `[starter] enabled`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/onboarding/starter-channel` | `receive` **and** a verified `PairingBinding` (paired app session), or `admin` (console/test harness) | Create or replay the request |
| `GET` | `/api/v1/onboarding/starter-channel/{request_id}` | `read` | Status of one request |
| `GET` | `/api/v1/onboarding/starter-channel` | `read` | The node's current request (latest non-refused, else latest), or 404 |

**Why `receive`, not `spend` or `admin`.** The newcomer moves no value out, opens nothing and changes no config; it asks to be paid into a channel, which is "create the means to be paid" (`docs/security/AUTH_SCOPES.md` §receive). Loopback `/auth/local` tokens also hold `receive`, so the handler additionally requires `auth.pairing.is_some()` (`konsensus-api/src/auth.rs:447-458`); a loopback-only token gets `403 paired_session_required`. No Admin token is involved anywhere in the app path.

POST request (`deny_unknown_fields`):

```json
{ "request_id": "3f0c0b7e-5d7a-4a43-9b1e-2f3c4d5e6f70" }
```

Response (POST 202 on create, 200 on replay; GET 200):

```json
{
  "request_id": "3f0c0b7e-…",
  "state": "requested | opening | ready | refused",
  "reason": null,
  "retry_allowed": false,
  "retry_after_unix": null,
  "network": "signet",
  "hub_node_id": "<64 hex>",
  "hub_ln_pubkey": "<66 hex>",
  "capacity_sats": 100000,
  "push_sats": 10000,
  "channel_id": "<hex|null>",
  "funding_txid": "<hex|null>",
  "verified": false,
  "created_at": 1761040000,
  "updated_at": 1761040012
}
```

`capacity_sats`/`push_sats` are null until the hub states them; `verified` is true only in `ready` (§7).

Errors (body `{ "error", "code", "retry_allowed", … }`, same shape as `konsensus-api/src/error.rs:150-180`):

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request_id` | Not a UUIDv4 |
| 403 | `paired_session_required` | Token has `receive` but no pairing binding |
| 403 | (scope error) | Missing `receive` |
| 400 | `not_dispatched` + `reason` | **Proven nothing happened:** no row written, no frame sent, no LN connect. Same or new `request_id` may be retried after fixing the cause. `reason` ∈ `starter_disabled`, `network_not_allowed`, `hub_not_configured`, `trust_no_reserve_required`, `money_not_ready`, `hub_unsupported` (hub connected and did not advertise `starter_hub_v1`) |
| 409 | `starter_already_requested` | Another non-refused request exists; body carries its `request_id` and state. One starter per node |
| 409 | `operation_mismatch` | Same `request_id` but the configured hub changed since it was stored |
| 503 | `disk_low` | Existing refusal, `retry_allowed: true` |
| 404 | `not_found` | GET of an unknown id |

A row that was persisted is never reported as `not_dispatched`, even if the hub is offline: it is `202 requested` and the worker keeps delivering. A hub refusal is not an HTTP error: it is `200` with `state: "refused"`.

## 5. Persistence and idempotency

Migration `031_starter_requests.sql` (SQLite + PostgreSQL, plus the encrypted wrapper), two tables; each node uses the one for its role.

**Newcomer: `starter_requests`**

| Column | Notes |
|---|---|
| `request_id` TEXT PK | UUIDv4 from the app. **Idempotency key.** |
| `hub_node_id`, `hub_ln_pubkey`, `network` | Bound at creation; mismatch on replay → 409 |
| `state`, `reason`, `retry_allowed`, `retry_after_unix` | §6.1 |
| `capacity_sats`, `push_sats`, `channel_id`, `user_channel_id`, `funding_txid` | From hub status, then confirmed locally |
| `verified_at`, `created_at`, `updated_at`, `last_sent_at`, `send_attempts` | |
| Partial unique index on `hub_node_id WHERE state <> 'refused'` (plus the API check) | At most one live request per node |

**Hub: `starter_grants`**

| Column | Notes |
|---|---|
| `request_id` TEXT PK | Same id as the newcomer's; replays hit this row |
| `requester_node_id`, `ln_pubkey`, `network`, `invite_id` (nullable), `source_ip_bucket` (`/24` or `/48`, no full IP) | |
| `state`, `reason` | §6.2 |
| `capacity_sats`, `push_sats` | Copied from config at admission; config changes do not alter admitted rows |
| `utc_day` | `YYYY-MM-DD` at admission; daily cap = count of non-refused rows for today |
| `open_operation_id` | = `request_id`, the key in `channel_open_operations` (migration 030, `docs/v2/EXACTLY-ONCE-OPERATIONS.md` §Channel opens) |
| `channel_id`, `user_channel_id`, `funding_txid`, `created_at`, `updated_at` | |
| Partial unique on `requester_node_id WHERE state <> 'refused'`; same on `ln_pubkey` | One starter per node and per LN key, enforced by the database, not by a scan |

Refused rows are terminal on both sides. Retrying after a retryable refusal means a **new** `request_id`; the partial indexes allow it. A different `request_id` for a node that already has a live or `ready` grant is answered `refused / already_served` and carries the original id.

## 6. State machines

### 6.1 Newcomer (the API states)

| From | Event | To |
|---|---|---|
| — | POST passes §4 checks; row committed | `requested` |
| `requested` | Hub `StarterStatus received` | `requested` (update `updated_at`) |
| `requested` | Hub `opening`, or LDK shows a pending inbound channel from `hub_ln_pubkey` | `opening` |
| `opening` | Hub `ready`, **and** §7 verification passes | `ready` (terminal) |
| `requested`/`opening` | Hub `refused` | `refused` (terminal, hub reason) |
| `opening` | Hub says `ready` but §7 fails for 10 min | `refused` / `verify_failed` |
| `requested` | No hub `StarterStatus` for 24 h | `refused` / `hub_no_response`, `retry_allowed: true` |
| `opening` | No channel visible locally 6 h after hub `opening` | `refused` / `open_not_observed`, `retry_allowed: true` |

A locally verified channel from the hub promotes to `ready` even if the hub's `ready` frame was lost.

**Restart recovery (newcomer).** On startup and every 15 s: for each `requested`/`opening` row, re-run local channel verification; if the hub session is up and `last_sent_at` is older than the backoff, resend `StarterRequest`. No state is derived from elapsed time except the two explicit timeouts above.

### 6.2 Hub

| State | Wire state | Entered when | Restart recovery |
|---|---|---|---|
| `admitted` | `received` | Signature, network and policy (§6.3) pass; row committed with counters in the same transaction | Proceed to open; caps were already charged |
| `opening` | `opening` | `channel_open_operations` row written **before** dispatch, then `open_channel_with_funding` | Replay #331: if the operation recorded a channel, or `list_channels` shows one to `ln_pubkey` with this `user_channel_id` → keep/advance; proven non-dispatch (`PaymentNotDispatched`) → back to `admitted`, max 3 attempts then `refused/open_failed`; otherwise stay `opening` (`outcome_uncertain`), raise metric, **never open again** |
| `ready` | `ready` | `ChannelReady` for that channel (0-conf, so usually seconds) | Terminal |
| `refused` | `refused` | Any §6.3 refusal, or 3 proven non-dispatches | Terminal |

The open call: `open_channel_with_funding(ln_pubkey, peer_addr_from_list_peers, capacity_sats, announce = false, FundingOptions { priority: <config>, max_funding_fee_sats: Some(<config>) }, push_msat = Some(push_sats * 1000))` (`konsensus-core/src/traits/lightning.rs:904`). An exact fee rate is never passed (`ldk.rs:3190`).

If ONB5 is also enabled on the hub, an ONB5 `Opening`/`Accepted` invite for the requester counts as the node's one starter (`already_served`), and a starter grant marks a matching pending invite `Accepted` on `ready`.

### 6.3 Hub admission policy (checked in this order, inside one DB transaction)

| # | Check | Refusal `reason` | `retry_allowed` |
|---|---|---|---|
| 1 | `[starter_hub] enabled`, hub network is signet/regtest, `request.network` equals it | `starter_disabled` / `network_mismatch` | false |
| 2 | `ln_sig` verifies over CANON for this session's mesh id | `ln_signature_invalid` | false |
| 3 | Admission mode: `invite` → a pending, unexpired hub-issued invite bound to `requester_node_id` (`Storage::find_pending_invite_for_invitee`); `open_capped` → none needed | `not_invited` | false |
| 4 | No live/ready grant for this node id or LN key; no ONB5 open for it; no existing channel to `ln_pubkey` | `already_served` (+ original id) | false |
| 5 | Rate limits: per requester ≤ 1 new admission / 10 min; `open_capped` only: per source `/24`/`/48` ≤ `per_ip_per_day` | `rate_limited` | true, `retry_after` |
| 6 | Today's non-refused grants < `max_opens_per_day` (UTC day, persisted) | `daily_cap_reached` | true, next 00:00 UTC |
| 7 | `opening` grants < `max_concurrent_opens` | `hub_busy` | true, +10 min |
| 8 | Σ `capacity_sats` of non-refused grants + this ≤ `lifetime_budget_sats` | `budget_exhausted` | false |
| 9 | LN peer `ln_pubkey` is connected to the hub (`list_peers`) | `ln_peer_not_connected` | true, +1 min |
| 10 | Funding fee preview (`funding_fee_quote`) ≤ `max_funding_fee_sats` | `fee_too_high` | true, +1 h |
| 11 | Hub on-chain spendable ≥ capacity + `max_funding_fee_sats` + 25,000 anchor reserve | `hub_insufficient_funds` | true, +1 h |
| 12 | Hub LDK capacity ceilings (`max_channel_capacity_sats`, total) | `hub_capacity` | false |

Sizes are **config, never request**: the request carries no amount. Startup validation: `push_sats ≤ capacity_sats / 2` (same rule as `payments.rs:1064-1068`), `capacity_sats ≤ 200,000` (the newcomer's waiver cap, `docs/UPGRADING.md:97-99`), `capacity_sats ≤ lightning.max_channel_capacity_sats`.

Unprivileged peers. In `invite` mode, `issue_invite` already whitelists the invitee atomically (`invites.rs:416-434`), so the request arrives on a privileged connection (`konsensus-message/src/transport/handshake.rs:402`); an unprivileged `StarterRequest` is dropped and counted as new `PrePaymentReason::StarterBeforeInvite`. In `open_capped` mode, `StarterRequest` is the **only** frame added to the pre-payment carve-out (`session_handler.rs:105-135`), and the hub answers a stranger at most once per 10 min per peer. P2 is untouched: the carve-out admits a request, never a message, and grants no privilege.

## 7. Newcomer verification

`ready` requires all of these from the newcomer's **own** LDK state (`list_channels`), never from the hub's word:

| Check | Expected |
|---|---|
| Counterparty | `hub_ln_pubkey` (= selected provider) |
| Announce | Private (not announced) |
| Type | Anchor channel, admitted under the `trust_no_reserve` waiver (capacity ≤ 200,000) |
| Capacity | = hub-stated `capacity_sats`, and ≤ `lightning.max_channel_capacity_sats` |
| Our balance | `outbound_capacity_msat + our reserve ≥ push_sats * 1000 − 1,000 msat` (the push is ours) |
| Usable | `is_channel_ready` (0-conf from the trusted provider, `vendor/ldk-node/src/event.rs:1404-1410`) |
| Identity | `channel_id`/`funding_txid` equal the hub's `StarterStatus`, when stated |

The verified fields are written to the row with `verified_at`; GET shows `verified: true`. The app can show "Money ready · 10,000 sats" from this alone.

## 8. Signet guard (enforced in the node)

| Layer | Rule |
|---|---|
| Startup, both roles | `[starter] enabled` or `[starter_hub] enabled` requires `bitcoin_network()` ∈ {`signet`, `regtest`} (`konsensus-node/src/config.rs:820`). Anything else (mainnet, testnet, unknown backends such as LND/LNbits that do not state a network) → startup config error `starter_network_not_allowed` |
| Mainnet flag | `allow_mainnet` exists in both sections, defaults `false`, and `true` is **rejected at startup** in this release with `starter_mainnet_not_approved`. Lifting it is a code change after Rasmus says GO |
| Newcomer POST | Re-checks network → `not_dispatched / network_not_allowed` |
| Hub, per request | `request.network` must equal the hub's network, checked again immediately before `open_channel_with_funding` |
| Regtest | Allowed only so the E2E fixtures can run; documented as test-only |

## 9. Doctrine checks

| Constraint | How this design meets it |
|---|---|
| Principle 2 | Unchanged. The request is a control frame, not a message; every accepted message still pays ≥ 1,000 msat at the gate. The push is channel balance, not a free send |
| No custodial credit | The push is the newcomer's own balance in a 2-of-2 channel, no clawback (T4a). The hub keeps no ledger, IOU or account for the user |
| No Cashu default | No ecash code path is touched or added |
| No cloud AI | The node contacts only its configured hub over the mesh and LN. No HTTP client is added |
| No Admin to the app | App uses `receive` + pairing binding only |
| "No automatic onboarding opens" | Still true: opens need an owner request **and** `[starter_hub] enabled` on the hub. Defaults off on both sides |
| T4a | Opt-in per node, exit-able (close any time), never the only path (direct channels, LSPS2 top-up, own funds remain) |

## 10. Tests

| Layer | Test |
|---|---|
| Wire | `StarterRequest`/`StarterStatus` round-trip; unknown-variant decode on an old peer is a clean drop |
| Auth | POST with loopback token → 403 `paired_session_required`; paired `read`-only → 403; paired `receive` → 202; `admin` → 202; `scope_coverage_tests` stays green |
| API | Same id replay → 200 same body; different id while live → 409 with existing id; changed hub → 409 `operation_mismatch`; each `not_dispatched` reason writes no row and sends no frame (assert storage + transport mocks) |
| Signet guard | Startup refuses mainnet/testnet/unknown network for both sections; `allow_mainnet = true` refused; hub refuses `network_mismatch` |
| Signature | Bad sig, sig for another mesh id, sig for another hub → `ln_signature_invalid`, no grant row |
| Hub policy | One test per §6.3 row; daily cap survives restart (reopen SQLite); concurrent duplicate requests (same id, and two ids same node) produce exactly one open (partial unique index) |
| Hub idempotency | Replay after `ready` returns the stored channel; replay during `opening` never calls `open_channel_with_funding` twice (counting mock) |
| Crash boundaries | Kill after grant commit / after operation row / after dispatch / after `ChannelPending`; restart reaches `ready` or `opening(uncertain)`, never a second open |
| Proven non-dispatch | `PaymentNotDispatched` → back to `admitted`; third time → `refused/open_failed` |
| Newcomer recovery | Restart in `requested` resends; restart in `opening` with channel present → `ready` without hub frame; 24 h / 6 h timeouts with a mock clock |
| Verification | Wrong counterparty, announced, capacity mismatch, push missing, capacity > 200,000 → never `ready` |
| Unprivileged | `invite` mode drops stranger frame + counter; `open_capped` answers once per 10 min |
| Regtest E2E | Extend the `three_node` fixture: empty-wallet newcomer with `trust_no_reserve`, hub with `[starter_hub]`; POST → `ready`; then a paid message newcomer → third node via the hub settles at the gate |
| PostgreSQL | Migration 031 parity in the existing ignored PG workflow |

## 11. Rollout

**PR split.**
1. **PR-1 (hub + wire + storage):** frames, `starter_hub_v1` capability, migration 031, `sign_message`/`verify_message`/`connect_peer` trait methods, `onboarding/starter_hub.rs` worker, admission, metrics. Off by default.
2. **PR-2 (newcomer + API):** `[starter]` config, API routes, newcomer worker and verification, status capability, regtest E2E, `docs/UPGRADING.md` + `docs/ops` page.

**Config.**

```toml
# Newcomer
[starter]
enabled = false            # feature flag
hub_node_id = ""           # 64-hex mesh id; hub LN key = lightning.liquidity.selected_provider
allow_mainnet = false      # true refused at startup in this release

# Hub (dedicated non-lockable signet hub)
[starter_hub]
enabled = false            # feature flag; refused with --home / --remote-unlock
admission = "invite"       # "invite" (T4a) | "open_capped" (needs GO, §12 Q1)
capacity_sats = 100000     # T4a signet decision
push_sats = 10000          # T4a signet decision
funding_priority = "economy"
max_funding_fee_sats = 2000
max_opens_per_day = 20
max_concurrent_opens = 4
lifetime_budget_sats = 2000000
per_ip_per_day = 3         # open_capped only
allow_mainnet = false      # true refused at startup in this release
```

Metrics (hub): `konsensus_starter_requests_total{result}`, `_opens_total`, `_refusals_total{reason}`, `_uncertain_opens`, `_capital_committed_sats`, `_gift_sats_total`.

**Order.** Merge PR-1 → enable on the signet hub only → merge PR-2 → enable `[starter]` on the two north-star test nodes → app ships the button against `starter_channel_request_v1`. Rollback is `enabled = false`; existing channels are unaffected.

Out of scope: idle reclaim (Option A H3), invite issuance service (H5), mainnet sizes, app UI.

## 12. Open questions for Rasmus

1. **Admission mode on signet.** T4a decided invite-gated starters. Invites need the hub operator to know the newcomer's node id first, which is a manual step until H5 exists. Ship `invite` only (recommended for the two north-star users), or also allow `open_capped` on signet for beta testers?
2. **Scope.** `receive` + mandatory pairing binding (recommended; no CLI), or a dedicated `starter` scope granted at the control socket like `front_door` (one console touch)?
3. **Signet numbers.** `max_opens_per_day = 20`, `lifetime_budget_sats = 2,000,000` (20 starters), `max_funding_fee_sats = 2,000`: OK?
4. **Which hub.** T4a calls for a dedicated non-lockable signet hub. Which node is it, and who funds its signet wallet (capacity + 25,000 reserve per channel)?
5. **Mainnet.** Funding vehicle, gift size and reclaim period are still open from T4a; `allow_mainnet` stays hard-refused until then.
6. **Idle reclaim.** Can M7a ship without H3 (14-day cooperative reclaim) on signet, with reclaim as a follow-up?
7. **Disclosure.** Approve the app line: "MindLink routes your payments and can see who pays whom; it cannot read your messages."
