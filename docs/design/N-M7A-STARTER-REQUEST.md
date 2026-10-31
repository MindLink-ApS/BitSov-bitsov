# N-M7a — Newcomer starter-channel request + status API (Option A, signet)

Original design baseline. Source read at `origin/main` `e8ed587` (v0.3.0-rc19 prep). Paths are under `crates/` unless stated. The implementation amendments below supersede the original proposal where noted.

**Goal (M7).** A brand-new user gets a hub-funded starter channel from inside the app, with no command line, so two users on their own nodes can message, call and pay each other from iPhone and Mac.

**Scope.** One owner-requested starter channel per node, funded by the hub from its own wallet under Option A / T4a (`docs/DESIGN-REASONING.md` T4a). Signet only, invite-only. Implementable in two PRs (§11).

**Decided (21 Oct):** invite-only admission for v1 (no open mode); `receive` scope + verified paired session, no Admin; signet caps 20 opens/day, 2,000,000 sats lifetime, 2,000-sat funding-fee cap; ship without idle reclaim on signet (reclaim is required before mainnet); the hub logs node id and amount only, and retains no IP address or LN alias.

## 1. Why rc18/rc19 has no app-callable path

| Path | Why it does not work from the app | Where |
|---|---|---|
| `POST /invites`, `POST /invites/accept` | `ScopedAuth<Admin>`; Admin is never grantable to a pairing | `konsensus-api/src/handlers/invites.rs:279`, `:450`; `docs/security/pairing.md` §Scopes |
| `POST /onboarding/start` `tier: "light"` | Needs Admin, and only writes `OnboardingStateRecord`; nothing is sent to anyone | `handlers/onboarding.rs:162-185` |
| ONB5 auto-channel worker | Opens with no push. It also passes `Some(fee_rate)` to `open_channel` (`onboarding/auto_channel.rs:372-378`), which LDK refuses before dispatch (`konsensus-lightning/src/ldk.rs:3190-3197`), so on an LDK hub ONB5 never opens at all. Tracked separately in node issue #349 | as cited |
| `POST /payments/open-channel` with `push_sats` | Spends the **executing** node's own funds; `ScopedAuth<Spend>` with unpaired authority; paired budget grants cannot open or push | `handlers/payments.rs:991-1075`; `docs/UPGRADING.md:115-121` |
| Status | No request object exists, so there is no status to poll | — |

`docs/UPGRADING.md:119-120`: "No automatic onboarding opens are enabled." This design keeps that sentence true: every open is an explicit owner request admitted by an explicitly enabled hub policy (§9).

## 2. Roles

| Role | Who | Does | Never does |
|---|---|---|---|
| **Newcomer node** | The new user's own node (home box, Pi, Umbrel, owner VM) | Accepts the owner's request from the paired app, persists it, signs it with its LN key, sends it to its configured hub, verifies the resulting channel locally, reports status | Spends, opens a channel, changes config, or contacts any service other than its configured hub |
| **Hub node** | The dedicated non-lockable MindLink signet hub (T4a) | Checks the invite and caps, opens a private 0-conf channel to the newcomer with a fixed push from its **own** wallet, reports status | Lends, records a balance owed, issues ecash, or opens without a persisted admitted request |
| **App** | Paired Mac / iPhone app | Generates a UUIDv4 `request_id` once, POSTs, polls GET, shows 4 states | Holds Admin or Spend for this flow |

Preconditions on the newcomer (written by the app's config template, Option A A1; checked at request time):
an LDK backend; `[lightning.liquidity] enabled = true`, `selected_provider = <hub LN pubkey>` with `trust_no_reserve = true` (N1, #326); the hub in `[[peers]]` (so it is whitelisted and dialled); and `[starter] enabled = true, hub_node_id = <hub mesh id>`.

Precondition on the hub: a pending, unexpired invite bound to the newcomer's node id, issued by the hub operator with the existing Admin `POST /api/v1/invites` (`invites.rs:279`). Issuing it whitelists the invitee atomically (`invites.rs:416-434`). This is an operator step on the hub, never in the app.

## 3. Message flow and channel choice

**Channel: the existing Noise_XX mesh transport session, as two new control frames.** Not the E2EE Double Ratchet message path, because:

1. Every UKM message must be paid (P2, `konsensus-core/src/gate.rs`). The newcomer has 0 sats; requiring a paid message to ask for the first sats is a deadlock.
2. X3DH/ratchet setup is refused before payment for non-privileged peers (`konsensus-node/src/session_handler.rs:105-135`, `SessionBeforePayment`), and the newcomer is not privileged on the hub's side until the invite whitelists it.
3. The request is protocol metadata between two nodes, not user content. The Noise session already authenticates both mesh node ids and encrypts the frame; the same reasoning is why `Frame::LightningInfo` travels there (`konsensus-message/src/wire.rs:844`, `session_handler.rs:437-469`).
4. LN custom messages were rejected: they bind only the LN key, need new LDK plumbing, and would add a second request path beside the mesh.

Because the invite whitelists the newcomer, its connection to the hub is privileged (`konsensus-message/src/transport/handshake.rs:402`). **No pre-payment carve-out is added.** The hub drops a `StarterRequest` from an unprivileged connection and increments a new `PrePaymentReason::StarterBeforeInvite` counter; it does not answer.

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
    state: String,                    // "received" | "opening" | "ready" | "refused"
    reason: Option<String>,           // refusal code, §6.3
    retry_after_unix: Option<u64>,
    original_request_id: Option<Uuid>,// set with reason "already_served": the node's live/ready grant
    capacity_sats: Option<u64>,
    push_sats: Option<u64>,
    channel_id: Option<String>,
    funding_txid: Option<String>,
},
```

`CANON = "bitsov-starter-v1\n{network}\n{hub_mesh_id}\n{newcomer_mesh_id}\n{request_id}\n{ln_pubkey}"`. It binds the LN key to the Noise-authenticated mesh id, so nobody can make the hub fund a third party's LN node, and "one per LN key" is meaningful. New trait methods `LightningProvider::sign_message` / `verify_message` wrap `vendor/ldk-node/src/lib.rs:2056`, `:2062`; other backends return `PaymentNotDispatched`.

The hub advertises `Capability::Custom("starter_hub_v1")` in Hello/HelloAck only while `[starter_hub] enabled` (`konsensus-node/src/node.rs:736`).

```
App                    Newcomer node                         Hub node
 | POST starter-channel  |                                       |
 |  {request_id}         | checks §4 + preconditions             |
 |                       | persist row: requested                |
 | 202 requested  <------|                                       |
 |                       | LN connect(hub, persist=true)         |
 |                       |== Noise: StarterRequest ============> | verify sig, network, invite, caps (§6.3)
 |                       |                                       | reserve caps + persist grant: admitted
 |                       | <========== StarterStatus received == |
 |                       |                                       | channel_open_operations row (#331)
 |                       |                                       | open_channel_with_funding(push)
 |                       | <========== StarterStatus opening === | (channel_id, funding_txid)
 |                       | LDK: inbound 0-conf anchor channel    |
 |                       |   from selected provider, waiver ok   |
 |                       | <========== StarterStatus ready ===== | on ChannelReady
 |                       | local verification (§7) -> ready      |
 | GET -> ready <--------|                                       |
```

Resending `StarterRequest` with the same `request_id` is also the status query: the hub answers from its persisted row and never repeats work. The newcomer resends on every (re)connect to the hub while non-terminal, with backoff 15 s → 30 → 60 → 120 → 300 s (capped at 300 s, indefinitely).

The newcomer's starter worker opens its LN connection to the hub (new `LightningProvider::connect_peer(pubkey, addr, persist)`; address from the selected provider entry). The hub opens over that connection: `connect_peer_if_necessary` short-circuits when connected (`vendor/ldk-node/src/connection.rs:40-48`), and the hub passes the address from `list_peers()` (`PeerDetails.address`). No NAT traversal, no vendor patch.

## 4. Newcomer API

Capability: `starter_channel_request_v1` in `/api/v1/status` `api_capabilities` (`handlers/health.rs:309`), only while `[starter] enabled`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/onboarding/starter-channel` | `receive` **and** a verified `PairingBinding`. No other token is accepted, Admin included | Create or replay the request |
| `GET` | `/api/v1/onboarding/starter-channel/{request_id}` | `read` | Status of one request |
| `GET` | `/api/v1/onboarding/starter-channel` | `read` | The node's current request (latest non-refused, else latest), or 200 `not_requested` with hub discovery |

**Why `receive`, not `spend` or `admin`.** The newcomer moves no value out, opens nothing and changes no config; it asks to be paid into a channel, which is "create the means to be paid" (`docs/security/AUTH_SCOPES.md` §receive). Loopback `/auth/local` tokens also hold `receive`, so the handler additionally requires `auth.pairing.is_some()`. `AuthUser::from_request_parts` populates `pairing` only after `check_pairing_binding` has verified the client id and epoch against the durable pairing record (`konsensus-api/src/auth.rs:497-506`). A token without a binding, including a key-proof Admin token, gets `403 paired_session_required`. Tests use paired credentials.

POST request (`deny_unknown_fields`):

```json
{ "request_id": "3f0c0b7e-5d7a-4a43-9b1e-2f3c4d5e6f70" }
```

Response (POST 202 on create, 200 on replay; GET 200):

```json
{
  "request_id": "3f0c0b7e-…",
  "state": "requested | opening | ready | refused",
  "detail": null,
  "reason": null,
  "retry_allowed": false,
  "retry_after_unix": null,
  "original_request_id": null,
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

`capacity_sats`/`push_sats` are null until the hub states them. `verified` is true only in `ready` (§7). `detail` is an informational sub-state on non-terminal rows (`hub_unreachable`, `hub_silent_24h`, `channel_pending`, `verify_mismatch`) and never ends a request.

Errors (body `{ "error", "code", "retry_allowed", … }`, same shape as `konsensus-api/src/error.rs:150-180`):

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request_id` | Not a UUIDv4 |
| 403 | `paired_session_required` | Token has `receive` but no verified pairing binding |
| 403 | (scope error) | Missing `receive` |
| 400 | `not_dispatched` + `reason` | **Proven nothing happened:** no row written, no frame sent, no LN connect. Same or new `request_id` may be retried after fixing the cause. `reason` ∈ `starter_disabled`, `network_not_allowed`, `hub_not_configured`, `trust_no_reserve_required`, `money_not_ready`, `hub_unsupported` (hub connected and did not advertise `starter_hub_v1`) |
| 409 | `starter_already_requested` | Another non-refused request exists; body carries its `request_id` and state. One starter per node |
| 409 | `operation_mismatch` | Same `request_id` but the configured hub changed since it was stored |
| 503 | `disk_low` | Existing refusal, `retry_allowed: true` |
| 404 | `not_found` | GET of an unknown id |

A row that was persisted is never reported as `not_dispatched`, even if the hub is offline: it is `202 requested` and the worker keeps delivering. A hub refusal is not an HTTP error: it is `200` with `state: "refused"`.

## 5. Persistence, idempotency and cap reservation

Migration `031_starter_requests.sql` (SQLite + PostgreSQL, plus the encrypted wrapper). Each node uses the tables for its role.

**Newcomer: `starter_requests`**

| Column | Notes |
|---|---|
| `request_id` TEXT PK | UUIDv4 from the app. **Idempotency key.** |
| `hub_node_id`, `hub_ln_pubkey`, `network` | Bound at creation; mismatch on replay → 409 |
| `state`, `detail`, `reason`, `retry_allowed`, `retry_after_unix`, `original_request_id` | §6.1 |
| `capacity_sats`, `push_sats`, `channel_id`, `user_channel_id`, `funding_txid` | From hub status, then confirmed locally |
| `verified_at`, `created_at`, `updated_at`, `last_sent_at`, `send_attempts` | |
| Partial unique index on `hub_node_id WHERE state <> 'refused'` (plus the API check) | At most one live request per node |

**Hub: `starter_grants`**

| Column | Notes |
|---|---|
| `request_id` TEXT PK | Same id as the newcomer's; replays hit this row |
| `requester_node_id`, `ln_pubkey`, `network`, `invite_id` | `ln_pubkey` is kept because uniqueness and open recovery need it. **No IP address, socket address or LN alias is stored** |
| `state`, `reason`, `attempts` | §6.2 |
| `capacity_sats`, `push_sats` | Copied from config at admission; config changes do not alter admitted rows |
| `utc_day` | `YYYY-MM-DD` at admission |
| `open_operation_id` | = `request_id`, the key in `channel_open_operations` (migration 030) |
| `channel_id`, `user_channel_id`, `funding_txid`, `created_at`, `updated_at` | Filled from the open result or from recovery (§6.2) |
| Partial unique on `requester_node_id WHERE state <> 'refused'`; same on `ln_pubkey` | One starter per node and per LN key, enforced by the database. While a grant is `admitted`/`opening`/`ready`, no replacement grant can be inserted |

**Hub: `starter_hub_counters` (single row, `id = 1`)** — the atomic reservation for the monetary caps.

| Column | Constraint |
|---|---|
| `id` INTEGER PK | `CHECK (id = 1)` |
| `utc_day` TEXT, `day_count` INTEGER | `CHECK (day_count >= 0)` |
| `inflight_count` INTEGER | `admitted` + `opening` grants; `CHECK (inflight_count >= 0)` |
| `committed_sats` BIGINT | Σ `capacity_sats` of `admitted`/`opening`/`ready` grants; `CHECK (committed_sats >= 0)` |

Admission runs in one transaction that holds the counter row exclusively: **PostgreSQL** `SELECT … FROM starter_hub_counters WHERE id = 1 FOR UPDATE`; **SQLite** `BEGIN IMMEDIATE` (one writer per database). Under that lock it (1) resets `day_count` to 0 if `utc_day` ≠ today, (2) checks `day_count < max_opens_per_day`, `inflight_count < max_concurrent_opens`, `committed_sats + capacity_sats ≤ lifetime_budget_sats`, (3) inserts the `starter_grants` row (the partial unique indexes fire here), (4) increments `day_count`, `inflight_count` and `committed_sats`, and commits. Two distinct newcomers racing for the last slot serialize on the row lock; the second sees the incremented counters and is refused. In-flight work counts from admission, not only from completion.

Counter changes on later transitions, each in its own transaction under the same lock:

| Transition | `inflight_count` | `day_count` / `committed_sats` |
|---|---|---|
| → `ready` | −1 | kept |
| → `refused` after **proven** non-dispatch | −1 | −1 / −capacity (refund) |
| `opening` stays uncertain | kept | kept (never refunded without proof) |

On startup the hub recomputes the counter row from `starter_grants` inside the same lock, so a crash between a grant update and a counter update cannot drift the caps.

Refused rows are terminal on both sides. A `refused` grant only exists when no channel was funded for it (§6.2). Retrying after a retryable refusal therefore needs a **new** `request_id`, which the partial indexes allow. A different `request_id` from a node that already has a live or `ready` grant is answered `refused / already_served` with `original_request_id` set.

## 6. State machines

### 6.1 Newcomer (the API states)

The newcomer enters `refused` **only** from a hub `StarterStatus refused`. Local time never ends a request, so a channel that the hub funds late still reaches `ready`.

| From | Event | To |
|---|---|---|
| — | POST passes §4 checks; row committed | `requested` |
| `requested` | Hub `StarterStatus received` | `requested` |
| `requested` | Hub `opening`, or the local channel list shows a channel from `hub_ln_pubkey` | `opening` |
| `requested`/`opening` | §7 verification passes (with or without a hub `ready` frame) | `ready` (terminal) |
| `requested`/`opening` | Hub `refused` | `refused` (terminal, hub reason) |
| `requested` | No hub `StarterStatus` for 24 h | stays `requested`, `detail: hub_silent_24h` |
| `opening` | A channel from the hub exists but fails §7 | stays `opening`, `detail: verify_mismatch` (surfaced to the app; operator investigates) |

**Adoption.** If the hub answers `already_served` with an `original_request_id` the newcomer has no row for (for example after a data-directory loss), the newcomer marks the new row `refused/already_served` and inserts the original id as `requested` with `detail: adopted`, then reconciles it like any other row.

**Restart recovery (newcomer).** On startup and every 15 s, for every `requested`/`opening` row: re-run §7 against the local channel list, and if the hub session is up and the backoff has elapsed, resend `StarterRequest`. This continues until the row is `ready` or the hub returns `refused`.

### 6.2 Hub

| State | Wire state | Entered when | Restart recovery |
|---|---|---|---|
| `admitted` | `received` | §6.3 passes; grant and cap reservation committed together (§5) | Proceed to open; caps already reserved |
| `opening` | `opening` | `channel_open_operations` row written **before** dispatch (operation id = `request_id`), then `open_channel_with_funding` | As below |
| `ready` | `ready` | `ChannelReady` for the recorded or recovered channel (0-conf, usually seconds) | Terminal |
| `refused` | `refused` | A §6.3 refusal, or a **proven** non-dispatch outcome below | Terminal |

The open call: `open_channel_with_funding(ln_pubkey, peer_addr_from_list_peers, capacity_sats, announce = false, FundingOptions { priority: <config>, max_funding_fee_sats: Some(<config>) }, push_msat = Some(push_sats * 1000))` (`konsensus-core/src/traits/lightning.rs:904`). An exact fee rate is never passed (`ldk.rs:3190`). LDK generates the `user_channel_id` internally (`vendor/ldk-node/src/lib.rs:1272-1295`), so the hub learns it only from the result.

| Open outcome | Hub action |
|---|---|
| `Ok(ChannelOpenResult)` | Record `channel_id`, `user_channel_id`, `funding_txid` on the operation and the grant; send `opening` |
| `PaymentNotDispatched` with reason `funding_fee_cap_exceeded` | Proven non-dispatch. `refused/fee_too_high`, `retry_allowed`, +1 h; refund the reservation |
| Other `PaymentNotDispatched` | Proven non-dispatch. Back to `admitted`; after 3 attempts `refused/open_failed`; refund on refusal |
| Any other error, timeout or crash before the result is recorded | Operation stays `pending`. Recover as below. **Never dispatch again** |

The construction-time fee cap is the fee proof: LDK checks the absolute PSBT fee against `max_funding_fee_sats` before signing (`vendor/ldk-node/src/wallet/mod.rs:359-363`), and `open_channel_with_funding` surfaces that failure as `PaymentNotDispatched` (`ldk.rs:2186-2188`). PR-1 replaces the formatted text with a stable reason constant `FUNDING_FEE_CAP_EXCEEDED` in `konsensus-core/src/traits/lightning.rs` (like `CHANNEL_CAPACITY_EXCEEDED`), so the hub does not match on prose. There is no pre-open fee preview: `funding_fee_quote` returns a rate, not an absolute fee.

**Recovery of a `pending` operation** uses #331's mechanism as it exists (`handlers/payments.rs:866-899`). PR-1 extracts it into a shared function. After the operation has been pending for 10 min, the hub lists channels to `ln_pubkey` and filters `capacity_msat == capacity_sats * 1000`:

| Matches | Result |
|---|---|
| Exactly one | Record it (`recovered: true`), grant → `opening`, then `ready` on `ChannelReady` |
| Zero or more than one | Operation `uncertain`; grant stays `opening`; metric `konsensus_starter_uncertain_opens` + log; **no re-dispatch, no refund**. An operator resolves it |

A unique match is sound for starters, because admission check 4 refuses any node that already has a channel to the hub, and the partial unique index allows one live grant per LN key.

If ONB5 is enabled on the hub (it cannot open on LDK today, #349), an ONB5 `Opening`/`Accepted` invite for the requester counts as the node's one starter (`already_served`). A starter grant marks the matching pending invite `Accepted` on `ready`.

### 6.3 Hub admission policy (in this order; 5–7 under the counter lock of §5)

| # | Check | Refusal `reason` | `retry_allowed` |
|---|---|---|---|
| 1 | `[starter_hub] enabled`, hub network is signet/regtest, `request.network` equals it | `starter_disabled` / `network_mismatch` | false |
| 2 | `ln_sig` verifies over CANON for this session's mesh id | `ln_signature_invalid` | false |
| 3 | A pending, unexpired hub-issued invite bound to `requester_node_id` (`Storage::find_pending_invite_for_invitee`) | `not_invited` | false |
| 4 | No live/ready grant for this node id or LN key; no ONB5 open for it; no existing channel to `ln_pubkey` | `already_served` (+ `original_request_id`) | false |
| 5 | `day_count < max_opens_per_day` (UTC day) | `daily_cap_reached` | true, next 00:00 UTC |
| 6 | `inflight_count < max_concurrent_opens` (admitted + opening) | `hub_busy` | true, +10 min |
| 7 | `committed_sats + capacity_sats ≤ lifetime_budget_sats` | `budget_exhausted` | false |
| 8 | Per requester: at most 1 new admission attempt per 10 min | `rate_limited` | true, `retry_after` |
| 9 | LN peer `ln_pubkey` is connected to the hub (`list_peers`) | `ln_peer_not_connected` | true, +1 min |
| 10 | Hub on-chain spendable ≥ capacity + `max_funding_fee_sats` + 25,000 anchor reserve | `hub_insufficient_funds` | true, +1 h |
| 11 | Hub LDK capacity ceilings (`max_channel_capacity_sats`, total) | `hub_capacity` | false |

Checks 8–11 run before the reservation transaction; a refusal there inserts a `refused` row without touching the counters. The funding fee is not pre-checked: it is enforced at construction (§6.2).

Sizes are **config, never request**: the request carries no amount. Startup validation: `push_sats ≤ capacity_sats / 2` (same rule as `payments.rs:1064-1068`), `capacity_sats ≤ 200,000` (the newcomer's waiver cap, `docs/UPGRADING.md:97-99`), `capacity_sats ≤ lightning.max_channel_capacity_sats`.

**Logging and retention (hub).** Log lines and metrics carry the requester's mesh node id, `request_id`, amounts, state and reason. They carry no IP address, socket address, LN alias or LN pubkey. The transport's peer address is not copied into any starter table or log.

## 7. Newcomer verification

`ready` is decided from the newcomer's **own** channel list (`LightningProvider::list_channels`), never from the hub's word. Today's `ChannelInfo` (`konsensus-core/src/traits/lightning.rs:201-223`) maps only id, peer, capacity, balances, `active` (= `is_usable`) and scid (`ldk.rs:2953-2963`). PR-2 adds the fields the checks need, all `Option` so that non-LDK providers stay unchanged:

```rust
// konsensus-core/src/traits/lightning.rs, struct ChannelInfo — appended
#[serde(default)] pub is_outbound: Option<bool>,        // LDK: ch.is_outbound
#[serde(default)] pub is_announced: Option<bool>,       // LDK: ch.is_announced
#[serde(default)] pub is_channel_ready: Option<bool>,   // LDK: ch.is_channel_ready
#[serde(default)] pub local_reserve_msat: Option<u64>,  // LDK: ch.unspendable_punishment_reserve.map(|s| s * 1000)
```

`channel_info()` in `ldk.rs` fills them from `vendor/ldk-node/src/types.rs` `ChannelDetails` (`:290`, `:317`, `:322`, `:329`). Other providers set `None`; `[starter]` already requires LDK.

| Check | Expected | Source |
|---|---|---|
| Counterparty | `peer_pubkey == hub_ln_pubkey` (= selected provider) | existing |
| Direction | `is_outbound == Some(false)` (the hub opened it) | new field |
| Private | `is_announced == Some(false)` | new field |
| Capacity | `capacity_msat == capacity_sats * 1000` stated by the hub, and ≤ 200,000 sats | existing |
| Push received | `local_balance_msat + local_reserve_msat ≥ push_sats * 1000 − 1,000` | existing + new field |
| Ready | `is_channel_ready == Some(true)` and `active` | new field + existing |
| Identity | `channel_id` / `funding_txo` equal the hub's `StarterStatus` values when stated | existing |

**Anchor type and reserve waiver are not checked, and cannot be:** `ChannelDetails` exposes no channel type or waiver evidence. They are guaranteed by admission instead. Since #329 the newcomer's LDK accepts inbound channels only as anchors, and on an empty wallet only under the selected-provider `trust_no_reserve` waiver for channels of at most 200,000 sats (`docs/UPGRADING.md:97-107`). A channel that passes the checks above therefore already passed both. The capacity check restates the waiver cap.

Verification runs before the owner can have spent anything from the channel, and `ready` is terminal, so later spending does not undo it. The verified values are written with `verified_at`, and GET shows `verified: true`.

## 8. Signet guard (enforced in the node)

| Layer | Rule |
|---|---|
| Startup, both roles | `[starter] enabled` or `[starter_hub] enabled` requires an LDK backend with `bitcoin_network()` ∈ {`signet`, `regtest`} (`konsensus-node/src/config.rs:820`). Anything else (mainnet, testnet, or a backend that states no network) is a startup config error, `starter_network_not_allowed` |
| Mainnet flag | `allow_mainnet` exists in both sections and defaults to `false`. `true` is **rejected at startup** in this release with `starter_mainnet_not_approved`. Lifting it is a code change after the owner says GO, and it also requires idle reclaim (Option A H3) to exist |
| Newcomer POST | Re-checks the network → `not_dispatched / network_not_allowed` |
| Hub, per request | `request.network` must equal the hub's network; checked again immediately before `open_channel_with_funding` |
| Regtest | Allowed only so the E2E fixtures can run; documented as test-only |

## 9. Doctrine checks

| Constraint | How this design meets it |
|---|---|
| Principle 2 | Unchanged. The request is a control frame on an invite-privileged connection, not a message, and adds no pre-payment carve-out. Every accepted message still pays ≥ 1,000 msat at the gate. The push is channel balance, not a free send |
| No custodial credit | The push is the newcomer's own balance in a 2-of-2 channel, with no clawback (T4a). The hub keeps no ledger, IOU or account for the user |
| No Cashu default | No ecash code path is touched or added |
| No cloud AI | The node contacts only its configured hub, over the mesh and LN. No HTTP client is added |
| No Admin to the app | The app uses `receive` + a verified pairing binding only; Admin tokens are refused on the POST |
| "No automatic onboarding opens" | Still true: an open needs an owner request, a hub-issued invite **and** `[starter_hub] enabled`. Both sides default off |
| T4a | Opt-in per node, exit-able (close any time), never the only path (direct channels, LSPS2 top-up and own funds remain) |

## 10. Tests

| Layer | Test |
|---|---|
| Wire | `StarterRequest`/`StarterStatus` round-trip including `original_request_id`; an old peer cleanly drops the unknown variant |
| Auth | POST with a loopback token → 403 `paired_session_required`; key-proof Admin token → 403 `paired_session_required`; paired `read`-only → 403; paired `receive` → 202; revoked pairing epoch → 401. The harness pairs a client for every positive case; `scope_coverage_tests` stays green |
| API | Same id replay → 200, same body; a different id while one is live → 409 with the existing id; changed hub → 409 `operation_mismatch`; each `not_dispatched` reason writes no row and sends no frame (assert storage + transport mocks) |
| Signet guard | Startup refuses mainnet, testnet, non-LDK and unknown networks for both sections; `allow_mainnet = true` refused; hub refuses `network_mismatch` |
| Signature | Bad sig, sig for another mesh id, sig for another hub → `ln_signature_invalid`, no grant row |
| Invite gate | No invite / expired / revoked → `not_invited`; an unprivileged `StarterRequest` is dropped silently and counted |
| Hub policy | One test per §6.3 row; counters survive restart (reopen SQLite) and are recomputed on startup |
| **Cap races** | N **distinct** invited newcomers race for the last daily slot, the last concurrent slot and the last lifetime budget, on SQLite and on PostgreSQL: exactly one is admitted, the others get the matching refusal, and the counters equal a recount |
| Hub idempotency | Replay after `ready` returns the stored channel; replay during `opening` never calls `open_channel_with_funding` twice (counting mock) |
| Crash boundaries | Kill after grant commit / after the operation row / after dispatch before the result / after `ChannelPending`. Restart reaches `ready` (unique peer+capacity match) or `opening` + `uncertain`; never a second open; never a refund without proof |
| Non-dispatch | `FUNDING_FEE_CAP_EXCEEDED` → `refused/fee_too_high` + refund; another `PaymentNotDispatched` → retry, third → `refused/open_failed` |
| Late funding | Newcomer offline > 24 h while the hub funds; on reconnect the row goes `requested` → `ready`. A second request id during that time → 409 locally, and `already_served` + adoption at the hub |
| Newcomer recovery | Restart in `requested` resends; restart in `opening` with the channel present → `ready` with no hub frame |
| Verification | Wrong counterparty, outbound, announced, capacity mismatch, push missing, capacity > 200,000, not ready → never `ready` (`verify_mismatch`) |
| Privacy | Hub log capture during a full flow contains no IP, socket address, LN alias or LN pubkey |
| Regtest E2E | Extend the `three_node` fixture: an invited empty-wallet newcomer with `trust_no_reserve`, and a hub with `[starter_hub]`. POST → `ready`; then a paid message from the newcomer to a third node via the hub settles at the gate |
| PostgreSQL | Migration 031 parity, and the cap-race test, in the existing ignored PG workflow |

## 11. Rollout

**PR split.**
1. **PR-1 (hub + wire + storage):** frames, the `starter_hub_v1` capability, migration 031 (all three tables), `sign_message`/`verify_message`/`connect_peer` trait methods, the `FUNDING_FEE_CAP_EXCEEDED` constant, #331 recovery extracted into a shared function, the `onboarding/starter_hub.rs` worker, admission, metrics. Off by default.
2. **PR-2 (newcomer + API):** `[starter]` config, API routes, the newcomer worker, the `ChannelInfo` fields and §7 verification, the status capability, the regtest E2E, `docs/UPGRADING.md` and a `docs/ops` page.

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
capacity_sats = 100000     # T4a signet decision
push_sats = 10000          # T4a signet decision
funding_priority = "economy"
max_funding_fee_sats = 2000
max_opens_per_day = 20
max_concurrent_opens = 4
lifetime_budget_sats = 2000000
allow_mainnet = false      # true refused at startup in this release
```

Admission is invite-only; there is no admission-mode key.

Metrics (hub, no peer-identifying labels): `konsensus_starter_requests_total{result}`, `_opens_total`, `_refusals_total{reason}`, `_uncertain_opens`, `_capital_committed_sats`, `_gift_sats_total`.

**Order.** Merge PR-1 → enable on the signet hub only → issue invites to the two north-star nodes → merge PR-2 → enable `[starter]` on those nodes → the app ships the button against `starter_channel_request_v1`. Rollback is `enabled = false`; existing channels are unaffected.

Out of scope: idle reclaim (Option A H3; not needed on signet, **required before mainnet**), the invite issuance service (H5), mainnet sizes, app UI, the ONB5 fix (#349).

## 12. Decision log

| Date (CST) | Question | Decision | By |
|---|---|---|---|
| 21 Oct 2026, 10:38 | **Signet hub and funder** (was open question 1) | The dedicated, non-lockable signet hub is the GCP `beta` signet VM, which already hubs the beta/Maya/Josh mesh. If beta is gone or unfit, fall back to a new small GCP VM. **Never** the Pi (the owner's lockable node) and **never** the Umbrel. MindLink funds it from signet faucets plus its own signet wallets; operators may top it up on their own (signet coins have no value). Budget: the 2,000,000-sat lifetime cap + 25,000-sat anchor reserve per channel + fees. | Owner-delegated (explicit GO 10:33) |
| 21 Oct 2026, 10:38 | **Mainnet** (was open question 2) | `allow_mainnet` stays hard-refused; this lane changes nothing. Shape for later: (a) the funding vehicle is MindLink's own hub node wallet, never a user's; (b) the gift is 10,000 sats per new person, one channel per node, daily cap unchanged; (c) **cooperative-only** reclaim (as T4a defines it, so it stays non-custodial) after 90 days with no outbound activity, and reclaim must be built and tested on signet before any mainnet switch; (d) going live on mainnet is a separate owner GO, because it sends sats to external nodes. | Owner-delegated (explicit GO 10:33) |

No open questions remain for signet. Mainnet stays behind (c) and (d), and the 20-per-day cap is re-checked at the mainnet GO.

### PR-2 implementation follow-ups: C3 and F4

C3 replaces the §7 current-balance heuristic with durable negotiated
`initial_push_msat` in LDK channel persistence. The newcomer verifies that value
and local channel readiness; ordinary spending cannot erase the proof. Old
channel records with no evidence fail closed. This is an optional LDK TLV
extension, not a SQL migration.

F4 keeps timeout retransmissions on the same UUID. To bound delivery work, there
are eight sends per mesh connection with §3's capped backoff; reconnect or an
explicit POST replay rearms the same operation. Local reconciliation never stops
on timeout. Retryable terminal hub refusals can create at most three successor
UUIDs, transactionally linked through `original_request_id` in the existing
031 table. Successor backoff is 10/20/40 minutes, or the hub's later retry time.
The original API request resolves to its current `operation_id`. An authenticated
`already_served` may revive the named original solely for reconciliation, including
a locally refused record that the hub subsequently admitted after refusal pruning.
See [operational details](../ops/starter-newcomer.md).


## Hub discovery and no-approval ruling (22 Oct)

The authenticated starter GETs expose read-only `hub_configured` and optional
`hub_alias`. Before any request, GET `/api/v1/onboarding/starter-channel` returns
200 with `{"state":"not_requested","hub_configured":false}` (or `true`, with an
optional alias). GET of an unknown explicit UUID still returns 404. Read scope
is required, including the existing verified pairing checks for paired tokens.
Unauthenticated callers receive no hub identity, endpoint, alias or balance.
The existing `starter_channel_request_v1` capability advertisement is unchanged.

`hub_configured` means starter is enabled and its mesh identity, whitelisted
peer, LN identity and LN address are configured. It does not assert reachability,
wallet readiness, an available invite or available hub funds. `hub_alias` is
optional `[starter] hub_alias` on the newcomer: an operator-supplied display name,
never a peer-discovered LN alias or an identifier used for routing. It is omitted
when no hub is configured. Discovery does not mutate config or request state.

The no-approval ruling retains `receive` plus a verified paired session for
POST, without adding an approval kind. The body is an explicit allowlist of
`request_id` only (`deny_unknown_fields`): caller-supplied cost, fee, amount or
push fields are refused before persistence, replay, or dispatch, even if zero.
All funding and push remain hub-to-newcomer. Any future newcomer-to-hub value
transfer must use the spend authorization path and cannot extend this request.

Idempotency remains scoped to this node's durable request UUID. Same-ID replays,
including concurrent replays, share one operation; terminal refusals alone permit
the bounded successor behavior documented in [newcomer operations](../ops/starter-newcomer.md).

The existing owner audit JSONL log records `starter.requested`, `starter.ready`
and `starter.refused` with the paired device ID in both `actor` and
`detail.paired_device_id`, request UUID, lineage root, state and refusal reason.
The request intent is flushed and synced before a new durable request can be
created; terminal outcomes are recorded from persisted state and retried on
reconciliation if logging fails. Replay does not replace the original device.
Automatic retries/adoption inherit the root's device identity. The log rebuilds
this attribution and event deduplication on restart; pre-upgrade requests with
no recorded origin are explicitly attributed to `unknown`, never guessed.
No SQL migration or new approval kind is introduced.

Conflicts before operation creation are separate `starter.request_conflict`
events, not terminal hub refusals; that UUID can be accepted later. Attribution
binds to the first device that requested the UUID. If authenticated adoption
revives a refused UUID, a new `starter.requested` transition allows its next
terminal outcome to be logged. Reconciliation repairs missing terminal events
for earlier operations even after a newer request becomes current. Startup
separates a crash-truncated journal tail before appending new records.
