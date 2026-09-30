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

## Migrations 020–028 (rc7 → rc8)

`v0.3.0-rc7` (`958e399`) ends at migration **019**. rc8 embeds **020–028** (nine
SQLite migrations). Upgrades from rc7 apply them automatically when using
embedded migrations. If you override `KONSENSUS_SQLITE_MIGRATIONS_DIR`, that
directory must include **all nine** (plus every earlier version the binary
embeds) or startup refuses.

| Ver | SQLite file | Purpose | PR |
| --- | --- | --- | --- |
| **020** | `020_pending_delivery_state.sql` | Pending-delivery `state` / `dispatched` columns | #103 |
| **021** | `021_paid_delivery_rejections.sql` | Paid-delivery rejection / retry-after columns | #103 |
| **022** | `022_receipt_bindings.sql` | Receipt bindings for duplicate ACKs | #103 |
| **023** | `023_delivery_price_quotes.sql` | Durable recipient-issued delivery price quotes | #103 |
| **024** | `024_outbox_operations.sql` | Exactly-once compose `outbox_operations` | #113 |
| **025** | `025_outbox_recovery.sql` | Bounded outbox recovery / replay tombstones | #116 |
| **026** | `026_outstanding_web_requests.sql` | Outstanding paid web 500/510 requests | #132 |
| **027** | `027_call_state.sql` | Durable 1:1 call state (kinds 400–403) | #131 |
| **028** | `028_call_request_hold.sql` | Call admission holds + pending request hash | #131 |

**Postgres** also ships dialect files for **021**, **024**, and **025** under
`crates/konsensus-storage/migrations/postgres/` (`021_paid_delivery_rejections.sql`,
`024_outbox_operations.sql`, `025_outbox_recovery.sql`). SQLite-only hosts ignore
those; Postgres hosts need them alongside the SQLite set when overriding the
migrations directory.


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
