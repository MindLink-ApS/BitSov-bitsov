# Upgrading a retained node

This note covers common failure modes when replacing the `konsensus` binary on a
production data directory without re-running `konsensus init`.

**rc8:** the items below are in `v0.3.0-rc8` (and current `main`). Read this before
swapping a long-lived data directory onto the new binary. Fresh `konsensus init`
installs are unaffected.

## MSRV (Rust 1.88+)

Workspace `rust-version` is **1.88** (raised from 1.75). The tree uses
`Option::is_none_or` (stabilized in 1.82), and the locked dependency set
requires Rust 1.88 (`home` 0.5.12 and related crates). Build with Rust 1.88 or
newer; CI continues to use stable. Verified with `rustup run 1.88.0 cargo check
--workspace --locked`.

## Missing `NODE_INITIALIZED` after upgrade (pre-#76/#77 nodes)

Nodes deployed before bootstrap (#76/#77) never wrote a `NODE_INITIALIZED` marker. After
upgrading the binary, `konsensus start` refuses with reason
`identity_and_state_without_marker`: identity material and wallet/channel state are present,
but the marker is absent.

This is expected for a healthy legacy installation — not a signal to wipe the data directory.
Finish the one-time marker write (the node will **not** do this automatically):

```bash
konsensus repair mark-initialized --config /path/to/konsensus.toml --confirm
```

Use the same config path you pass to `konsensus start` (`-c` / `--config`). The repair
writes `NODE_INITIALIZED` and nothing else, then normal startup proceeds.

See also [pairing security](security/pairing.md) for how the marker fits into bootstrap.

## Stale `KONSENSUS_SQLITE_MIGRATIONS_DIR`

Released binaries embed the full SQLite migration set. You normally **do not** need
`KONSENSUS_SQLITE_MIGRATIONS_DIR` on a production host.

If a systemd unit or shell profile still sets it to an **old on-disk migrations tree**
(from a July build, for example), the new binary may start against a database that never
receives migrations 020–028. That produces recurring storage errors (for example outbox
reconciliation failures, missing `outstanding_web_requests` for bound web replies, or
missing call-state tables) instead of a clean refusal.

From current releases, startup **fails closed** when the directory is missing any migration
version embedded in the binary. The error names the directory and the missing version numbers.

**Fix:**

1. Remove `KONSENSUS_SQLITE_MIGRATIONS_DIR` from the unit/environment so embedded migrations
   apply, **or**
2. Point it at a directory that includes **every** migration version the binary embeds (extra
   files are fine; the directory must be a superset).

After fixing the migrations source, restart the node. The node applies any pending schema
migrations itself on first open before serving traffic.

## Migrations 026–028 (web requests + calls)

rc8 embeds migrations **026–028**. Upgrades from a binary that stopped earlier apply them
automatically when using embedded migrations. If you override
`KONSENSUS_SQLITE_MIGRATIONS_DIR`, that directory must include all three or startup refuses:

| Ver | File | Purpose |
| --- | --- | --- |
| **026** | `026_outstanding_web_requests.sql` | Durable table binding zero-amount `KIND_WEB_MANIFEST` / `KIND_PAGE_RESPONSE` replies to an outstanding paid 500/510 request (#129, #132). |
| **027** | `027_call_state.sql` | Durable 1:1 call state (kinds 400–403): burned call ids, live phase, pending operation reservation (#131). |
| **028** | `028_call_request_hold.sql` | Bind a reserved signal to its request hash; hold incoming call signals until admission finalizes (#131). |

## `[pricing] call_msat`

rc8 prices a call **offer** (kind 400) with `[pricing] call_msat` (default **10 000** msat).
The value must be **> 0** or config validation refuses. Answers (401), ICE (402), and hangup
(403) keep `realtime_signal_msat`. Omit the key to take the default; set it explicitly if you
want a different offer price on this node.

```toml
[pricing]
call_msat = 10000
```

## STUN (app setting, not node config)

Call **media** is WebRTC in the end-user app. Across NATs the owner optionally sets a
`stun:host` or `stun:host:port` in app Settings. The node does **not** ship or require a
STUN/TURN server; there is no hard-coded STUN in genome or the app, and TURN is unsupported.
With no STUN configured, calls use host candidates only (same network or VPN). See
[`docs/v2/CALLS-PROTOTYPE.md`](v2/CALLS-PROTOTYPE.md).
