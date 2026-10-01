# Upgrading a retained node

This note covers two common failure modes when replacing the `konsensus` binary on a
production data directory without re-running `konsensus init`.

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
receives migrations 020–025. That produces recurring storage errors (for example outbox
reconciliation failures) instead of a clean refusal.

From current releases, startup **fails closed** when the directory is missing any migration
version embedded in the binary. The error names the directory and the missing version numbers.

**Fix:**

1. Remove `KONSENSUS_SQLITE_MIGRATIONS_DIR` from the unit/environment so embedded migrations
   apply, **or**
2. Point it at a directory that includes **every** migration version the binary embeds (extra
   files are fine; the directory must be a superset).

After fixing the migrations source, restart the node. The node applies any pending schema
migrations itself on first open before serving traffic.

## Disk admission floor

The top-level `konsensus.toml` setting `disk_free_floor_bytes` defaults to
**2147483648 bytes (2 GiB)**. Put it before any `[section]` header:

```toml
disk_free_floor_bytes = 2147483648
```

The node probes available space (excluding filesystem blocks reserved for root)
on the directory containing its configured mnemonic and `ldk/` state at startup,
every five seconds while running, and before new invoice/payment/channel dispatch.
Below the floor, or if probing fails, new work is refused with `disk_low`; the
owner-only `/api/v1/status` reports `disk_low`, `disk_free_bytes` (null on probe
failure), and `disk_free_floor_bytes`. HTTP refusals use 503 and code `disk_low`.
The refusal occurs before dispatch: no payment is sent or invoice issued by that
refused operation. Work already paid for, status and other reads, channel closes,
settlement reconciliation, recovery and shutdown remain available. Admission
resumes automatically when space is at least the floor. A value of zero disables
the reserve, but probe failures still refuse new work.

This is a reserve, not a guarantee against filesystem exhaustion: other processes
and already admitted work can consume it. It checks the local state filesystem;
separately mounted SQLite/backup paths and external LND storage require their own
operator monitoring. Embedded LDK also checks the same floor before claiming incoming HTLCs or
accepting new inbound channels, including invoices issued before space dropped.
A refused HTLC is failed without revealing the preimage. Already claimed payments
continue through persistence/recovery. It does not make a remote Lightning server
stop accepting payments or channels; its own storage/admission policy remains
that server's responsibility.

## State generation and rollback safety

Before opening SQLite or constructing LDK, startup durably writes
`STATE_GENERATION` beside the configured mnemonic (the same parent as `ldk/`).
The marker uses format `bitsov-state-v1:<generation>`; this release introduces
binary/state compatibility generation **1**. Future incompatible migrations or
LDK persistence changes must increment `STATE_GENERATION` in the binary before
state is opened. Publication uses a temporary file, file fsync, atomic rename,
and directory fsync. A process lease (`STATE_GENERATION.lock`) prevents concurrent
nodes from changing generation while another node owns this state.

An older guard-aware binary refuses a higher generation with
`state_generation_newer`; malformed or unreadable markers also refuse startup.
Keep the newer binary with its current data directory. Do not delete or lower
the marker to force a downgrade. Existing installations without a marker adopt
the current generation on first guarded startup. Binaries released before this
guard cannot enforce it.

**Never roll back a live data directory after the first LDK start.** Restoring a
pre-upgrade directory, VM snapshot, or old channel-state backup can broadcast a
revoked commitment and get a channel punished, losing funds. This applies even
when the binary's generation has not changed. The marker detects an older binary
opening newer retained state; it cannot detect restoring the whole directory
(including the marker) to an older snapshot, or establish channel-state freshness.
It is not permission to restore stale LDK state. Preserve the latest state and
follow [the recovery guidance](v2/RECOVERY.md); recovery commands themselves are
not gated by the disk admission floor.

## Chain-view status compatibility (#158)

Owner `GET /api/v1/status` now returns `chain_view.trust_level: "own_node"`
for Bitcoin Core, replacing `"trustless"`. Update app comparisons to the new
value. It describes configured ownership, not proven validation or readiness;
Esplora remains `"third_party"`.

The new nullable `chain_sync` reports observed LDK wallet failures with
`state: "stalled"`, `since` (Unix seconds), and the fixed kind
`last_error_kind: "sync_failed"`. See [chain source status](CHAIN-SOURCE.md#privacy-and-status).
