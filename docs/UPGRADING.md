# Upgrading a retained node

This note covers common failure modes when replacing the `konsensus` binary on a
production data directory without re-running `konsensus init`.

**rc8:** the items below are in `v0.3.0-rc8` (and current `main` through #154). Read
this before swapping a long-lived data directory onto the new binary. Fresh
`konsensus init` installs are unaffected. For VMs, also read **VM / multi-host
upgrade rules** and **Encrypted seed / custody** below.

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

## STUN (optional node listener + app setting)

Call **media** is WebRTC in the end-user app. Across NATs each peer needs a public
address. **Off by default** the node does not listen for STUN. The owner may enable an
optional binding-only responder:

```toml
[calls]
stun_listen = "0.0.0.0:3478"   # UDP; omit to keep it off (default)
```

- RFC 5389 **binding request → XOR-MAPPED-ADDRESS** only. No TURN, no relay, no auth,
  no per-call state (#136).
- **Firewall:** open **UDP** on the chosen port to hosts that should learn their mapped
  address (typically the public Internet, or a VPN path). Binding fails boot if the
  address cannot be listened on.
- Owner-only `GET /api/v1/status` reports `stun_port` and, when the node has a dialable
  public host, `stun_url` (`stun:host:port`). `/health` reports neither.
- In the app, Settings → Calls still requires the owner to set (or confirm) a
  `stun:host[:port]`; nothing switches on automatically. With no STUN URL saved, calls
  use host candidates only (same network / VPN). TURN is unsupported.

See [`docs/v2/CALLS-PROTOTYPE.md`](v2/CALLS-PROTOTYPE.md).

## VM / multi-host upgrade rules (rc8)

These rules apply when replacing the binary on a long-lived data directory (Mac pilot
or hosted VMs). They are operational constraints, not a claim that a particular
upgrade script is safe.

1. **Rollback window.** Restoring the old data directory after the new binary has
   started LDK and published Lightning state can get a channel **punished (funds
   lost)**. Rollback of the data dir (and any restored `migrations.old`) is only
   allowed **before the first LDK start on the new binary**. After that, roll
   forward only.
2. **No seed copy.** Do not write an extra mnemonic copy during upgrade. Leave the
   existing seed path alone (plaintext or encrypted).
3. **One VM at a time.** Upgrade hosts sequentially so calls, meetings, and front
   door are not split across mixed builds longer than necessary. Aim for the Mac
   pilot and each VM to end on the same build.

Migrations **020–028** apply at first open on the new binary (rc7 ends at **019**).
Confirm the live schema before upgrade; never run the old binary against the new
SQL after migrations have applied.

## Encrypted seed, `--password-file`, and custody labeling

Seed encrypt and `--password-file` shipped in #153 (via #150). Custody labeling and
the remote-signer design note shipped in #154.

- Interactive `konsensus start` can prompt for the seed password. A **systemd** unit
  cannot type into that prompt. For an encrypted seed under systemd, use the opt-in
  `--password-file <path>` (regular file, mode `0600`, owner-only, **no symlink**).
  Starting this way leaves Touch ID approvals off (`seed_password_not_typed`).
- A password file is readable by any process running as that user (including a paired
  app). It protects against **other OS users**, not same-user compromise.
- An encrypted seed on a VM the operator controls is **not** self-custody of a
  different kind: the node decrypts the seed into that machine's memory. Label it
  honestly via `[identity] hosted = true` (or cloud tier) so owner `/status`
  reports `custody_mode: hosted_custody`. Prefer that over implying the VM is a
  remote signer.
- `remote_signer` in `/status` is **reserved**. No config in this release produces
  it; see [`docs/protocol/REMOTE-SIGNER.md`](protocol/REMOTE-SIGNER.md) for the
  design only.
