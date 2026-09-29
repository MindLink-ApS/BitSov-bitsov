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
receives migrations 020–026. That produces recurring storage errors (for example outbox
reconciliation failures, or missing `outstanding_web_requests` for bound web replies)
instead of a clean refusal.

From current releases, startup **fails closed** when the directory is missing any migration
version embedded in the binary. The error names the directory and the missing version numbers.

**Fix:**

1. Remove `KONSENSUS_SQLITE_MIGRATIONS_DIR` from the unit/environment so embedded migrations
   apply, **or**
2. Point it at a directory that includes **every** migration version the binary embeds (extra
   files are fine; the directory must be a superset).

After fixing the migrations source, restart the node. The node applies any pending schema
migrations itself on first open before serving traffic.

## Migration 026 (`outstanding_web_requests`)

rc8 embeds migration **026**, which adds the durable table used to bind zero-amount
`KIND_WEB_MANIFEST` / `KIND_PAGE_RESPONSE` replies to an outstanding paid 500/510 request
(#129, #132). Upgrades from a binary that stopped at 025 apply 026 automatically when
using embedded migrations. If you override `KONSENSUS_SQLITE_MIGRATIONS_DIR`, that
directory must include `026_outstanding_web_requests.sql` or startup refuses.
