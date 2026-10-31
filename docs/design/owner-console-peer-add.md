# N4 — Live peer add over the owner control socket

Design note, docs only. Source read at `origin/main` `ce7fb53` (clone at `e66c268`, same tree). All paths are under `crates/` in the Konsensus repo. No code changed.

## 1. Problem

On rc17 the only two ways to add a peer are:

| Path | Cost for a non-technical owner |
|------|--------------------------------|
| Edit `[[peers]]` in `konsensus.toml` and restart | Restart re-prompts for the seed password; a typo in TOML stops the node (`config.rs:1500-1510`, `deny_unknown_fields`). |
| `POST /api/v1/peers` | Needs `ScopedAuth<Admin>` (`handlers/peers.rs:193`), i.e. an owner token minted via `sign-challenge` + `/auth/token` (`docs/releases/v0.3.0-rc17.md:10`). |

Goal: `konsensus peer add --node-id <64hex> --addr <ip:port> [--label <text>]` against the running node, no token, no restart, no config edit; the peer is persisted, whitelisted, dialed immediately and comes back after restart.

## 2. What exists today (with file:line)

### 2.1 Owner control socket

| Aspect | Where | Fact |
|--------|-------|------|
| Path | `konsensus-api/src/control.rs:62` | `<data_dir>/control.sock` (`SOCKET_FILE`). |
| Bound only under `--owner-control` | `konsensus-node/src/main.rs:1879-1912` | Bind failure is fatal; sidecar/packaged app never has the socket (`control.rs:19-23`). |
| Auth | `control.rs:900-909` | Unix socket, `chmod 0600` right after bind. Any process running as the node's uid (or root) can connect. No token, no per-request auth. |
| Wire format | `control.rs:998-1027` (`serve_connection`), `control.rs:1121-1140` (`send`) | One newline-delimited JSON request per line, one JSON response per line; multiple requests per connection allowed. |
| Request enum | `control.rs:65-177` | `ControlRequest`, `#[serde(tag="op", rename_all="kebab-case", deny_unknown_fields)]`. Encoded by hand in `encode_request` (`control.rs:1032-1114`) because the enum deliberately has no `Serialize`/`Debug`/`Clone` (it carries a mnemonic). |
| Response enum | `control.rs:180-235` | `ControlResponse::{Status, Describe, Ok{detail}, Error{message}}`, tag `result`. |
| Pure dispatch | `control.rs:423-638` | `handle(ctx: &ControlContext, req)` — pairing-service operations only, no `AppState`. |
| Stateful dispatch | `control.rs:1144-1191` | `handle_local(ctx, Option<&Arc<AppState>>, req)`: `ApproveGift` is routed to `handlers::sponsor::approve_owner` with `MeteredSpend::owner_control(state)` (`metered.rs:82-87`, actor = this node's own id, scope `Spend`). Everything else falls through to `handle`. `AppState` is attached in `main.rs:1906` via `ControlServer::with_approval_state`. |
| CLI side | `konsensus-node/src/cli/owner.rs:207-224` | `socket_path(config)` = `data_dir_of(config)/control.sock`; `send()` wraps the connect error with the "must be running with `--owner-control`" hint. `report()` at `owner.rs:258-272` prints `Ok.detail` / fails on `Error`. Output passes through `terminal_safe` (`owner.rs:237-251`) because the socket peer is not trusted to emit escape codes. |
| Simplest existing command (template) | `cli.rs:402-412`, `main.rs:257`, `owner.rs:913-915` | `konsensus pair-window --seconds N` → `ControlRequest::OpenWindow` → `Ok{detail}`. No confirmation. |

### 2.2 Consent model on the socket — which ops need the typed nonce

The module doc (`control.rs:37-47`) draws the line:

- **Nonce-confirmed ops** (`Grant`, `GrantFrontDoor`, `ApproveDeviceKey`, `ApproveReplacement`): the node prints `<LABEL> CODE <nonce>` plus a short code to `/dev/tty` only (`pairing.rs:783-803` `OwnerTerminal`, `pairing.rs:973-1012` `console_challenge`), falling back to a protected owner file when headless. The CLI reads the code from stdin (`owner.rs:442-456`). Reason: those ops move value or replace identity and the *requester* is an untrusted paired app.
- **Tuple-is-consent ops** (`ApproveFirstContact`, `ApproveGift`, `Revoke`, `RevokeGrant`, `RevokeDeviceKey`, `ResetGrantBreakers`, `OpenWindow`): no nonce. The complete owner-typed argument set is the consent, "they require an owner-managed node and OS account outside the paired app's control" (`control.rs:45-47`).

Adding a peer is owner-initiated (nobody requested it over HTTP), and admission is already given away without nonce by `OpenWindow` and `ApproveFirstContact`. So `peer add` belongs in the second class. See §5 for the residual risk.

### 2.3 How `POST /peers` admits a peer (`handlers/peers.rs:192-253`)

```
1. NodeId::from_hex(node_id)                         peers.rs:197
2. addr.parse::<SocketAddr>()                        peers.rs:200   (IP:port only, no DNS; cf. docs/operations/reachability.md:48)
3. label.len() <= MAX_PEER_LABEL_LEN (256)           peers.rs:21, 205-211
4. registry.write().add(PeerEntry{..auto_connect})   peers.rs:220-223   -> gate whitelist cache (konsensus-message/src/peer.rs:132-136)
5. transport.add_to_whitelist(&node_id)              peers.rs:226       -> transport admission set (transport/mod.rs:1044)
6. transport.supervise_peer(&node_id, addr)          peers.rs:229       -> background dial + reconnect (transport/mod.rs:1076-1095, supervisor.rs:117-120)
7. storage.upsert_peer(Peer{address, display_name})  peers.rs:233-240   -> durable `peers` table (sqlite.rs:1303, postgres.rs:1395)
8. audit_log.record(PEER_ADDED, actor, {peer_node_id, addr})  peers.rs:242-249
```

`POST /peers/:id/connect` (`peers.rs:413-451`) additionally does a blocking `transport.connect()` (`peers.rs:445`) before `supervise_peer`, so the caller learns whether the first dial succeeded. The new command wants that behaviour: "dial it live" with a result the owner can see.

Note: `add_peer` does not reject `node_id == self` (only `import_peers` does, `peers.rs:533-537`). The shared function should.

### 2.4 Persistence and config-vs-DB precedence at boot

| Step | Where | Behaviour |
|------|-------|-----------|
| Config peers first | `konsensus-node/src/node.rs:446-456` | Every `config.peers` entry is added to `PeerRegistry` with its real `addr`, `label`, `auto_connect`. |
| DB peers merged after | `node.rs:464-470`, `merge_persisted_peers` at `node.rs:708-728` | `storage.list_peers()`; rows whose `node_id` is already in the registry are **skipped** ("config.peers take precedence", `node.rs:700-701`). Others are added with `address` parsed (or sentinel `0.0.0.0:0` if absent) and `auto_connect: false`. |
| Supervision at start | `node.rs:535-549`, `supervisor.rs:112-120` | `start()` supervises **every** registry entry regardless of `auto_connect` ("Contacts reconnect regardless of the legacy startup auto_connect flag", `supervisor.rs:111`). `track_peer` refuses sentinel addresses (`supervisor.rs:144-148`). |
| Transport whitelist at start | `node.rs:479` | `TransportConfig.whitelist = peer_registry.whitelist()` after the merge, so DB peers are admitted. |
| DB row shape | `konsensus-storage/src/models.rs:114-125` | `Peer { node_id, address: Option<String>, last_seen, display_name, metadata: json }`. `upsert_peer` is a single `ON CONFLICT ... COALESCE` upsert (`sqlite.rs:1303-1330`); `invite_ref` / `whitelist_source` metadata keys are preserved across upserts (`models.rs:139`). |

Consequence: a peer written to the `peers` table with a routable address **survives restart, is whitelisted, and is dialed** — no config edit is required. That is exactly what `POST /peers` relies on today, and `peer add` can rely on the same path.

Limitation: if the same `node_id` is also present in `[[peers]]`, the config row wins at every boot (`node.rs:716-718`); a live `peer add` that changes its address would be overwritten on restart. The command should detect this and say so (see §4.4, §8).

### 2.5 Audit, rate limits

- Audit API: `AuditLog::record(event, actor, detail)` (`konsensus-api/src/audit.rs:54`); event constants at `audit.rs:67-75` (`peer.added`, `peer.removed`, `peer.updated`, ...). Actor convention: node id hex, or `"system"` (`audit.rs:45`). The control-socket gift path uses the node's own id as actor (`metered.rs:84`).
- No rate limiting on the control socket (`rate_limit.rs` is HTTP/tunnel only). Each connection is a spawned task looping over lines (`control.rs:944-948`, `1009`). Fine for a 0600 local socket; there is no amplification because only same-uid callers can connect.
- No existing `peer` subcommand in the CLI (`cli.rs:17-419`); `whitelist backup|restore` (`cli.rs:471-508`) works offline against the DB and is the closest relative.

## 3. CLI surface

```
konsensus peer add    --node-id <64hex> --addr <ip:port> [--label <text>] [--yes] [-c konsensus.toml]
konsensus peer list   [-c konsensus.toml]                                   (optional, same PR if cheap)
konsensus peer remove --node-id <64hex> [--yes] [-c konsensus.toml]         (optional, follow-up)
```

`konsensus peer add` flow (mirrors `cmd_pair_window` / `cmd_grant_revoke`, `owner.rs:828-845, 913-915`):

1. Parse and validate locally before touching the socket: `NodeId::from_hex` (64 hex), `SocketAddr` parse (reject hostnames with the same wording as `reachability.md:48`), label ≤ 256 bytes, label passes `terminal_safe` unchanged (no control chars).
2. Print what will happen, using data the CLI can compute itself:
   ```
   Add contact
     node id:        <64hex>
     fingerprint:    <8 hex>          (NodeId::short_fingerprint, as /peers shows)
     address:        203.0.113.7:9735
     label:          "Bob"
   This node will accept paid traffic from that key and keep a connection to it.
   Press Enter to continue, or Ctrl-C to cancel.
   ```
   `--yes` skips the prompt (for scripts and runbooks). The prompt is a client-side courtesy, not a security boundary — see §5.
3. `send(config, ControlRequest::AddPeer{..})` → `report(resp)`.
4. On `Ok`, `detail` tells the owner whether the first dial succeeded, e.g.
   `added Bob (ab12cd34) at 203.0.113.7:9735 — connected` or
   `added ... — not reachable yet (connection refused); the node keeps retrying. Check the address and that the peer has whitelisted <our id>.`
   Exit code 0 in both cases (the peer *is* added); the second case is a warning line, not a failure.

The socket-missing error already carries the right hint (`owner.rs:214-222`): "must be running and started with `--owner-control`".

Clap: new `Command::Peer { #[command(subcommand)] command: PeerCommand }` in `cli.rs` next to `Whitelist` (`cli.rs:257-260`); `PeerCommand::Add { node_id, addr, label, yes, config }`. Dispatch in `main.rs` next to `Command::PairWindow` (`main.rs:257`).

## 4. Control-socket message shape

### 4.1 Request (`control.rs` `ControlRequest`)

```rust
/// Admit a contact the owner typed at the console: persist it, whitelist it,
/// dial it. The complete tuple is the consent (same class as `OpenWindow`).
AddPeer {
    /// Peer node id, 64 hex.
    node_id: String,
    /// `ip:port`; no hostnames.
    addr: String,
    /// Optional display label, at most 256 bytes.
    #[serde(default)]
    label: Option<String>,
},
```

Wire: `{"op":"add-peer","node_id":"…","addr":"203.0.113.7:9735","label":"Bob"}`.
Add the matching arm to `encode_request` (`control.rs:1044-1111`, `fields!("add-peer", node_id, addr, label)`) and a fixture line to `wire_tests` (`control.rs:1199-1213`).

### 4.2 Response

Reuse `ControlResponse::Ok { detail }` / `Error { message }`. No new variant needed; `detail` carries the human line from §3 step 4. If a machine-readable field is wanted later for the app, add `#[serde(default)] connected: Option<bool>` to `Ok` — but keep it out of this slice.

### 4.3 Dispatch

`AddPeer` needs `AppState` (storage, transport, registry, audit), which the pure `handle()` does not have. Route it exactly like `ApproveGift`:

- `handle()` (`control.rs:423`): `ControlRequest::AddPeer { .. } => Error { "peer admission requires the running node's services" }` (same shape as the `ApproveGift` arm at `control.rs:562-564`, keeps the pure function total).
- `handle_local()` (`control.rs:1144`): match `AddPeer` before the fallthrough; require `state` with the same `owner_control_enabled() && Arc::ptr_eq(pairing, ctx.service)` guard used at `control.rs:1160-1170`; call the shared function from §4.4; map `Ok(outcome)` → `Ok{detail}`, `Err(ApiError)` → `Error{message: e.to_string()}`.

### 4.4 Reused internal function (the one refactor)

Extract the body of `add_peer` (`peers.rs:197-249`) plus the live dial from `connect_peer` (`peers.rs:445-448`) into one function both callers use:

```rust
// konsensus-api/src/handlers/peers.rs
pub struct AdmitPeerOutcome { pub entry: PeerEntry, pub dialed: Result<(), String> }

/// Validate, persist, whitelist, supervise and (optionally) dial one owner-admitted peer.
/// `actor` is the audit actor; `source` lands in the audit detail and in
/// `Peer.metadata["whitelist_source"]`.
pub async fn admit_peer(
    state: &Arc<AppState>,
    actor: &str,
    source: &'static str,          // "http_admin" | "owner_control"
    req: AddPeerRequest,
    dial_now: bool,
) -> Result<AdmitPeerOutcome, ApiError>
```

Order inside (changed from today's `add_peer`, for durability-first):

1. validate: hex, `SocketAddr`, label length, **reject `node_id == state.identity.node_id()`** (new; copy of `peers.rs:533-537`).
2. `storage.upsert_peer(Peer{address, display_name, metadata: {"whitelist_source": source}})` — persist **before** touching live state so a crash between steps leaves a row the next boot re-admits (today `add_peer` persists last, `peers.rs:233`).
3. `registry.write().add(entry)` (`peers.rs:220-223`).
4. `transport.add_to_whitelist` (`peers.rs:226`).
5. if `dial_now`: `transport.connect(&node_id, &addr)` with `tokio::time::timeout(10s)`; record the error string, never fail the admission on it (`connect_peer` does fail, `peers.rs:448`; for the console we want "added, not reachable yet").
6. `transport.supervise_peer` (`peers.rs:229`, after the explicit dial, as `connect_peer` does at `peers.rs:447`).
7. `audit_log.record(events::PEER_ADDED, actor, {peer_node_id, addr, label, source, connected})`.

Callers:

- HTTP `add_peer` → `admit_peer(&state, &_auth.node_id, "http_admin", req, dial_now=false)`; response unchanged (`peer_response(&entry, false, ..)`). Existing tests for `POST /peers` keep passing; only the persist-before-whitelist ordering changes.
- Control socket → `admit_peer(&state, &state.identity.node_id().to_hex(), "owner_control", req, dial_now=true)`; actor is the node's own id, matching `MeteredSpend::owner_control` (`metered.rs:84`).

Config-collision check (§2.4 limitation): `handle_local` can see neither `config.peers` nor the file, and `AppState` does not carry the config peer list. Cheapest honest option: the **CLI** reads `konsensus.toml` (it already has the path) and warns before sending: "this node id is also in `[[peers]]` in konsensus.toml; the config entry wins at the next restart — remove it there if you want this address to stick." No node-side change.

## 5. Security considerations

| Topic | Finding | Decision |
|-------|---------|----------|
| Who can reach `control.sock` | Same uid as the node, or root (`control.rs:900-909`, mode 0600 in `data_dir`). Not reachable over loopback TCP, browsers, other OS users, SSH port-forwards (`control.rs:30-33`). The sidecar app has `data_dir` access but the sidecar never binds the socket (`control.rs:19-23`, `main.rs:1879`). | Same trust boundary as `pair-window` and `approve-first-contact`. Acceptable. |
| Does it need the `/dev/tty` nonce like grants? | The nonce exists to stop an untrusted *requester* (paired app) from approving its own elevation (`control.rs:3-26`). `peer add` has no requester; the owner types the whole tuple. Whitelisting a key grants admission + outbound dial + paid-gate acceptance — not spend authority, not identity. `OpenWindow` (which lets a new client pair) already ships without a nonce. | **No node-side nonce.** CLI-side Enter/`--yes` prompt only (§3). Flagged as open question §8.1 in case reviewers want parity with `ApproveFirstContact`'s "exact tuple" style — which it already has. |
| Same-uid malware | Could already call `open-window`, `revoke`, `approve-first-contact`. A nonce for `add-peer` would not change that class; `/dev/tty` delivery is readable by the same uid anyway (the module doc says so, `control.rs:42-44`). | Document, do not engineer around. |
| Audit entry | `peer.added` with actor = node id, `source: "owner_control"`, `connected: bool`, plus `whitelist_source` metadata on the DB row (preserved key, `models.rs:139`). Distinguishes console adds from HTTP admin adds in both the audit log and `GET /peers` diagnostics. | Required. |
| Rate limits | None on the socket; `admit_peer` is one DB upsert + one dial. Dial has a 10 s timeout so a hostile address cannot pin the connection task. | None added. Cap label at 256 bytes (existing const). |
| Terminal injection | Label is echoed back in `detail`; CLI already routes socket text through `terminal_safe` (`owner.rs:237-251`). The node should also refuse labels with control characters at admit time so `GET /peers` consumers are safe too. | Add control-char check to `admit_peer`. |
| Self-add | `add_peer` today accepts own node id. | Reject in `admit_peer` (both callers). |
| Hostname in `--addr` | `SocketAddr` parse rejects it; consistent with `[[peers]]` (`reachability.md:48`). | Error message says "IP address and port only". |

## 6. Test plan

| Layer | File | Cases |
|-------|------|-------|
| Wire | `control.rs` `wire_tests` (`:1194-1223`) | Add `{"op":"add-peer","node_id":"…","addr":"127.0.0.1:9735","label":"Bob"}` and the `label` omitted form to the round-trip fixtures. |
| Pure dispatch | `control.rs` unit | `handle(ctx, AddPeer{..})` returns `Error` (no state) — mirrors `ApproveGift`. |
| Admission function | `konsensus-api/tests/peers_*` (existing `POST /peers` tests + `common::mod` state builders, `tests/common/mod.rs:983`) | `admit_peer`: (a) happy path: row in `storage.list_peers()`, `registry.get()` present, `transport.whitelist` contains id, `supervise_peer` called; (b) rejects self id; (c) rejects hostname addr; (d) rejects 257-byte and control-char labels; (e) `dial_now=true` with unreachable addr → `Ok` with `dialed: Err(..)`, row still persisted; (f) persist failure → `Err`, registry/whitelist untouched. |
| Socket end-to-end | `konsensus-api/tests/pairing_tests.rs` next to `owner_control_socket_permissions` (`:675`) | Bind `ControlServer` with `with_approval_state(state)`, `control::send(AddPeer)`, assert `Ok`, assert audit line `peer.added` with `source=owner_control`, assert `GET /peers` (Read token) lists it with `connected=false`. Also: server without `with_approval_state` → `Error("…requires the running node…")`. |
| CLI | `konsensus-node/tests/peer_add_cli.rs`, copy the fake-socket harness from `tests/grant_cli.rs:14-60` | (a) prints summary, waits for Enter, sends exactly one `add-peer` request with the given tuple; (b) `--yes` sends without prompt; (c) bad hex / hostname / long label exit non-zero **before** connecting (fake listener sees zero requests); (d) `Error{message}` from socket → non-zero exit, message shown via `terminal_safe` (feed an ANSI escape in the message and assert it is escaped); (e) no socket file → the "`--owner-control`" hint. |
| Node integration (restart survival) | `konsensus-node/tests/` (pattern: `local_bootstrap_cli.rs`, `locked_mode_tests.rs`) | Start node A with `--owner-control`, start node B, `konsensus peer add` B on A, assert A↔B connected via `GET /peers/connected`; stop A, start A again without touching `konsensus.toml`, assert B is whitelisted and the supervisor reconnects (poll `GET /peers` `connected=true`). Then the config-collision case: put B in `[[peers]]` with a different port, restart, assert registry shows the config port (documents the precedence). |
| Regression | existing `POST /peers`, `import`, `connect` API tests | Must pass unchanged after the `admit_peer` extraction. |
| Manual (home-node runbook) | `docs/operations/home-node.md` | One line: `konsensus peer add --node-id … --addr … --label <name>`, read the connected/not-reachable line, confirm in app. |

## 7. Estimate

| Piece | Size |
|-------|------|
| `admit_peer` extraction + self-id/control-char checks, HTTP caller switched | 0.5 d |
| `ControlRequest::AddPeer`, `encode_request`, `handle`/`handle_local` arms, wire fixture | 0.25 d |
| Clap `peer add`, `cmd_peer_add` with prompt/`--yes`, config-collision warning | 0.5 d |
| Tests (API socket e2e, CLI fake-socket, node restart integration) | 0.75 d |
| Docs: `docs/operations/home-node.md` peers section, `docs/security/AUTH_SCOPES.md` socket op list, rc18 release note | 0.25 d |
| **Total** | **~2.25 dev-days**, one PR (two if `peer list`/`remove` are added). Dual review per the usual rule; the control-socket change should get the security reviewer's eyes on §5. |

Files touched: `konsensus-api/src/control.rs`, `konsensus-api/src/handlers/peers.rs`, `konsensus-node/src/cli.rs`, `konsensus-node/src/cli/owner.rs`, `konsensus-node/src/main.rs`, tests as above, three docs.

## 8. Open questions

1. **Nonce or not.** §5 argues `add-peer` is a tuple-is-consent op like `open-window`. If the stronger form is wanted anyway, the cheap version is: node prints `PEER-ADD <fingerprint> CODE <nonce>` to `/dev/tty` via `console_challenge` (`pairing.rs:973`) and the CLI reads the code like `grant` does. Cost +0.5 d, and it breaks the headless/`--yes` path unless the protected-file fallback is used.
2. **`peer list` / `peer remove` in the same PR?** `list` is a `Status`-style read of `registry.all()` + `connected_peers()`; `remove` reuses `remove_peer` (`peers.rs:256-293`) after the same extraction. Both are small; `remove` of a `[[peers]]` entry has the same config-precedence caveat (it comes back at restart).
3. **Config precedence.** Should `merge_persisted_peers` (`node.rs:708`) let a DB row with a *newer* address override a config entry? Today config wins unconditionally. Leaving as-is and warning from the CLI is the minimal change; flipping it is a behaviour change for every existing node and needs its own note.
4. **`auto_connect` flag.** DB-loaded peers get `auto_connect: false` (`node.rs:725`) but are supervised anyway (`supervisor.rs:111-116`); the flag is legacy. `GET /peers` will show `auto_connect=false` for console-added peers after a restart even though they reconnect. Either store `auto_connect` in `Peer.metadata` and honour it in the merge, or drop the field from the API. Cosmetic; out of scope here.
5. **Dial timeout and wording.** 10 s is a guess; LDK/Noise handshake timing on a Pi may need 15 s. The "not reachable yet" line also needs to mention that the *other* node must whitelist us — when two owners connect their nodes, both run `peer add` pointing at each other.
6. **Packaged sidecar.** The desktop/phone app's sidecar never has `control.sock`, so this command is owner-run-node only (home node, Pi, release Mac). The app path for the same action remains `POST /peers` with an Admin token; nothing here changes that.
