# Upgrading a retained node

This note covers common failure modes when replacing the `konsensus` binary on a
retained data directory without re-running `konsensus init`.

**rc11 preparation (2026-10-07):** includes all rc10 changes since rc9
(`cd75c69`), plus #259–#266 through `52670e7`. rc10 was tagged at `83fb6c6`
but never published because tag CI failed on pairing-ticket revocation, fixed
by #266. Skip rc10 and upgrade directly to rc11. The release commit will be the
`main` HEAD after the rc11 docs/version PR merges. The rc9 and older procedures
remain below for nodes skipping releases: apply them first, then this one.

## rc9 → rc11 procedure

1. **Before stopping rc9**, reconcile pending payments, channel opens and LSPS2
   top-ups as for rc9. Upgrade one host at a time. Verify the replacement
   artifact against the signed `SHA256SUMS` (`SHA256SUMS.asc`, release key
   `B299274C200301714DC6F51A7C2D6F8AC842EF6E`) under
   [release policy](ops/RELEASE_POLICY.md). Then stop the node cleanly and keep
   the same config and data directory. Do not re-run `init`.
2. **State generation 2 makes the upgrade one-way.** The first rc11 start
   raises `STATE_GENERATION` to `bitsov-state-v1:2` before SQLite or LDK opens.
   With `--remote-unlock`, that happens at unlock, not while locked. After that,
   an rc9 binary refuses the directory with `state_generation_newer`. A stopped
   copy of the rc9 directory is a rollback option only **before** the first
   rc11 start. Never lower or delete the marker, and never restore a
   pre-upgrade LDK directory; see
   [state generation](#state-generation-and-rollback-safety). No numbered SQL
   migration was added: the embedded set remains **001–028**.
3. **No config change is required.** Every new key below is optional and
   defaults safely. Add any of them only after the binary is replaced: rc9
   rejects unknown fields, so a config containing `[dos_edge]`, `[node]`,
   `[tower.clients]` or `[lightning] our_to_self_delay_blocks` will not load
   on rc9.
4. **Peer doorway defaults change (#250).** `cookie_mode` now
   defaults to `adaptive` (was `disabled`), and the new `[dos_edge]` limits
   always apply. Under load, sources must return a stateless cookie before the
   node does Noise work. Peers that cannot answer a cookie challenge cannot
   connect while cookies are demanded. To keep the old cookie-free protocol, set
   top-level `cookie_mode = "disabled"` (above any table header); the rate and
   concurrency limits still apply. Many honest nodes behind one NAT or IPv6 /64
   share one budget, so on a shared network raise `connection_burst`,
   `handshake_burst`, `max_per_ip` or `max_per_subnet` carefully. The IPv4 /24
   aggregation is gone, so each IPv4 address now gets its own budget. Keep
   upstream firewall/SYN-flood protection. See
   [protecting the peer doorway](operations/dos-edge.md).
5. **Pricing floor (#245, #248, #253).** Every paid admission must now carry at
   least 1,000 msat, including discounted prices and older delivery quotes.
   Update custom or older senders that pay 1–999 msat. Advertised and
   first-contact prices may rise. They now include `min_admission_cost_msat`
   when it exceeds `chat_msat`, and a zero `chat_msat` quotes 1 sat. No config
   change is required; see [paid admission minimum](#paid-admission-minimum-t18).
6. **SCB restore and move-home (#246).** `konsensus scb restore` now always
   refuses, including preview. Update runbooks that relied on it. Use
   `konsensus move-home` on the healthy source, and restore the whitelist
   explicitly with `konsensus whitelist restore --from <file>`. While `ldk/move-home.json`
   exists, normal startup refuses: resume the maintenance command, and keep the
   journal with the live store. During move-home, LSPS2 service/client and
   `forward_to_private_channels` are forced off for the maintenance run only;
   the config is not changed. See
   [SCB restore lock and move-home](#scb-restore-lock-and-move-home-157).
7. **Box transport key (#244).** The first unlocked rc11 start creates
   `pairing/box-transport.key` (0600) and signs it into `identity/identity.json`.
   The data directory must be on a filesystem with hard links; key publication
   fails on exFAT/FAT. Preserve both files from then on and back them up with
   the identity. Paired clients learn the signed key on their next connection
   to the unlocked node.
8. **Remote unlock (#247) is opt-in** with `--remote-unlock`, which is an argv
   switch, not a config key. Follow [Remote unlock (U2)](#remote-unlock-u2)
   below before adopting it. The example
   [systemd unit](operations/konsensus.service) changed from `--owner-control`
   to `--remote-unlock --local-owner-device`. If you installed the old
   example, do not replace your unit unless you are adopting remote unlock.
   While locked, the node does not monitor channels or accept messages.
9. **Owner-device delegation (#251).** With `--local-owner-device` (which
   needs `--password-fd` or `--remote-unlock`), the node now keeps the owner signing key in zeroizing memory for the life of
   the process, so an enrolled owner device can approve another device. Without
   that flag, delegation is refused. Pending device-key requests created on rc9
   have no nonce: request them again to delegate. Check
   `owner_device_count` in `GET /api/v1/pair/device-keys`. Keep at least one
   non-phone owner device; console revoke and recovery are unchanged.
10. **Pairing tickets and box label (#252).**
    `konsensus pair-ticket --config <cfg> [--qr] [--ttl 24h]` needs
    `[remote_access]` with `listen_addr` and `advertised_endpoint`, Unix file
    locking, and, on an initialized node, one unlocked rc11 start first so
    `identity/identity.json` holds both signed transport proofs.
    It is refused while locked. Keep its output out of service journals and
    package logs: anyone holding the ticket can pair once as `read+receive`.
    The automatic five-minute first-pairing link is unchanged; the daemon only
    prints the protected file's path. Optionally set `[node] hosted_by`. See
    [enrollment tickets](operations/home-node.md#enrollment-tickets-and-box-labels).
11. **Remote first run (#256).** Only fresh
    installs are affected: `start --remote-unlock --local-owner-device` on a
    positively empty data directory serves two-phase bootstrap over the tunnel
    to the client that consumed a pre-bootstrap `pair-ticket`, then exits 75.
    The supervisor must restart on failure (`Restart=on-failure`) to come back
    locked for the first remote unlock. Retained nodes need no action.
12. **Longer breach window (#261, W0) is optional.** Under `[lightning]`,
    `our_to_self_delay_blocks` accepts 144–2016; omission retains LDK's 144.
    A value of 288 is about two days, with variable block times. It applies only
    to new channels in either direction, including LSPS2; existing channels keep
    their negotiated delay. Peers may refuse a longer value. This does not
    provide watchtower protection or lift the hub-only restriction.
13. **Local watchtower staging (#262–#265) is off by default.** Omit
    `[tower.clients]` or leave it empty to keep it off. Only the embedded LDK
    backend supports opt-in entries under `[tower.clients.NAME]`, each with
    `node_id` and `endpoint` (at most five). W1/W2a writes local candidates and
    encrypted outbox data under `ldk/tower/`, with owner-only
    `GET /api/v1/tower/status` diagnostics. It has **no transport, no payments,
    no generated acknowledgments and no active offline protection**. Coverage
    counts are `to_local_only`, not HTLC protection. The bounded outbox has no
    sender to drain it, and unsigned recovery data can still grow; enabling it
    later cannot recover all missed historical states. The hub-only restriction
    remains. See [local staging](operations/home-node.md#local-watchtower-staging-w2a-optional).
14. **Hardening and ticket revocation (#259, #266).** Owner front-door price
    overrides now respect the admission floor. Remove U+206A–U+206F and Unicode
    tag characters from any retained `hosted_by` label. Ticket replacement now
    revokes the old code even if file timestamp and length are unchanged; no
    ticket format or config migration is needed.
15. **After restart:** inspect authenticated `/api/v1/status` as in the rc9
    procedure. For remote unlock, also check `GET /api/v1/node/lock`.
    App-side remote unlock, delegation and tickets need an app build re-pinned to
    rc11; the node cannot establish app support.

### New config keys and switches (rc9 → rc11)

| Key / switch | Where | Default | Source |
|---|---|---|---|
| `cookie_mode` | top level | **`adaptive`** (was `disabled`); also `required`, `disabled` | #250 |
| `connections_per_second`, `connection_burst` | `[dos_edge]` | `10.0`, `40` | #250 |
| `handshakes_per_second`, `handshake_burst` | `[dos_edge]` | `2.0`, `8` | #250 |
| `max_pending`, `max_handshakes` | `[dos_edge]` | `128`, `64` | #250 |
| `max_per_ip`, `max_per_subnet` | `[dos_edge]` | `4`, `8` | #250 |
| `cookie_threshold`, `max_tracked_sources` | `[dos_edge]` | `32`, `4096` | #250 |
| `cookie_timeout_secs`, `handshake_timeout_secs` | `[dos_edge]` | `3`, `10` | #250 |
| `hosted_by` | `[node]` | unset (`null` in API) | #252 |
| `our_to_self_delay_blocks` | `[lightning]`, embedded LDK | unset (LDK uses `144`); optional `144`–`2016`, new channels only | #261 |
| `clients` | `[tower]` / `[tower.clients]` | empty (off); at most five named entries, embedded LDK only | #264 |
| `node_id`, `endpoint` | `[tower.clients.NAME]` | required per entry: unique compressed Lightning public key and `host:port`; endpoint is reserved, never contacted in W2a | #264 |
| `forward_to_private_channels` | `[lightning]` | `false` (unchanged since rc9, #226) | forced off only during `move-home` (#246) |
| `--remote-unlock` | `start` argv | off; excludes `--password`, `--password-file`, `--password-fd`, `--owner-control` | #247 |
| `konsensus pair-ticket [-c <cfg>] [--qr] [--ttl 24h]` | CLI | config `konsensus.toml`; TTL `24h`, `s`/`m`/`h`/`d`, max 365 days | #252 |
| `konsensus move-home [-c <cfg>] --destination <addr> [--fee-rate 2] [--confirm] [--password-fd <n>]` | CLI, owner's `/dev/tty` | preview unless `--confirm`; fee rate 1–10000; `--force-close <channel>` also needs `--confirm --confirm-force-close` | #246 |
| `konsensus whitelist restore --from <file> [-c <cfg>]` | CLI | explicit only | #246 |

`[dos_edge]` rejects unknown keys and zero, non-finite, out-of-range or
inconsistent limits (for example `max_per_ip` > `max_per_subnet`, or
`cookie_threshold` ≥ `max_handshakes`); see
[protecting the peer doorway](operations/dos-edge.md).
`[node]` rejects unknown fields; `hosted_by` must be 1–64 printable characters
without surrounding whitespace, control, bidi-override, zero-width or Unicode
tag characters. `[tower]` and its named clients reject unknown fields; there
are no tower pricing, retention or payment-cap config keys in W2a.

**Hubs and `forward_to_private_channels`:** rc11 does not change this key. An
ordinary LDK hub that forwards into its clients' unannounced channels still
needs `forward_to_private_channels = true` in `[lightning]`. The default is
false. An LSPS2 service hub (`[lightning.lsps2_service] enabled = true`)
enables private forwarding by itself. `konsensus move-home` disables
forwarding, LSPS2 service and LSPS2 client for the maintenance run only. Moving
a hub closes its client channels, and it forwards nothing during the run.
Clients need new channels to the destination hub, so tell them before moving a
hub.

## Remote unlock (U2)

Before enabling `--remote-unlock`, start unlocked once on U1 or newer, enroll an
owner device, and connect a supporting client so it pins the identity-signed box
transport key. Preserve `identity/identity.json` and `pairing/box-transport.key`.
The home-node systemd example now uses `--remote-unlock --local-owner-device`;
remove any password file or credential directive when adopting it. Existing
manual/descriptor startup remains available. New pairing while locked is not
supported. Remote first-run bootstrap on an empty data directory (#256) is
supported; see
[remote first run on an empty box](operations/home-node.md#remote-first-run-on-an-empty-box).
A locked node does not monitor channels. rc11 enforces this (#257): with
`--remote-unlock`, new channels in or out are refused with `HUB_ONLY_WHILE_LOCKABLE`
unless the peer is in `[lightning.liquidity] providers`; existing non-hub channels
are not closed, so close them first. Read
[the home-node runbook](operations/home-node.md) before changing unattended
startup. `--remote-unlock` is an argv switch, never a configuration setting.

**rc9 preparation:** covers `main` through #240 (`7fde729`), 2026-10-06.
Read this before replacing a retained node's binary. The older rc7 → rc8
procedure and compatibility inventory remain below for reference. Fresh rc9
`konsensus init` installs do not need retained-node marker repair. For VMs,
also read **VM / multi-host upgrade rules** and **Encrypted seed / custody**.

## SCB restore lock and move-home (#157)

SCB restore now always refuses, including preview and `--confirm`; there is no
bypass. Previous preview started a node from historical channel state and could
broadcast a revoked commitment. Do not downgrade to recover that behavior or
roll back a live LDK directory. Preserve backups for a compatible recovery
procedure. Whitelist sidecars must now be restored explicitly with
`konsensus whitelist restore`; they are no longer applied by SCB restore.

To move funds from a healthy node, stop the normal service and follow
[close and send home](operations/move-home.md). This owner-console command uses
current live state, cooperative closure, separate force-close consent for named
channels regardless of peer connection state, and exact sweep amount/fee
confirmation. It records `ldk/move-home.json` beside the live LDK database. Keep this journal together
with the live store: it binds the destination and records signed transactions
for idempotent replay. Normal startup refuses while the journal exists,
including after completion; resume the maintenance command instead. Do not
remove the journal or run an older binary against a migrating store. The new
node should have its own fresh identity. State generation increases to **2** so older generation-1 binaries refuse the
store instead of ignoring migration consent. No numbered SQL migration is added.

## Paid admission minimum (T18)

Receiving nodes now enforce at least **1,000 msat (1 sat) for every paid
admission**, including discounted prices and previously issued delivery quotes.
Higher prices and configured admission costs still apply. Older or custom
senders that pay 1–999 msat will be rejected even if a price table or old quote
listed less; update them to pay at least 1,000 msat before retrying. The current
API compose path already rounds up to whole sats. Zero-priced new admissions also
require the minimum. Replies bound to an outstanding paid page/manifest request
and authenticated retries of already accepted envelopes retain their existing
handling. No storage migration or configuration change is required.

## rc7 → rc9 procedure

1. Record the installed version, config path and selected chain source. Stop
   the node cleanly; preserve the latest data directory and verify your normal
   backup/recovery procedure. Do not re-run `init`, copy/export the seed, or
   delete state to resolve an upgrade refusal. Upgrade one host at a time.
2. Verify the replacement artifact's signed checksums and provenance under
   [release policy](ops/RELEASE_POLICY.md). Source builds require Rust 1.88+
   and the release lockfile. These preparation notes do not publish a release.
3. Remove stale `KONSENSUS_SQLITE_MIGRATIONS_DIR`, or ensure it contains every
   embedded SQLite migration **001–028**. rc7 ends at **019**; rc9 applies
   **020–028** at first database open. There are no new numbered migrations
   since rc8. Preserve the existing wallet, pairing, config and seed files;
   check free space against the 2 GiB default reserve.
4. Review the rc8 config/API inventory below and the rc9 changes in the next
   section. In particular, rc7 init writes `[pricing] web_content_msat = 50`:
   **raise it to at least `1000`** (1 sat), or remove it to use rc9's default.
   A retained value below 1000 causes startup validation to refuse, even with
   `[web] enabled = false`. Valid higher operator prices are preserved. Arrange
   encrypted-seed password input before restarting an unattended service.
5. Start rc9 with the existing config. A legacy identity without
   `NODE_INITIALIZED` refuses with **`identity_without_marker`** (identity only)
   or **`identity_and_state_without_marker`** (identity and retained state).
   If inspection confirms a healthy legacy installation, explicitly consent:

   ```bash
   konsensus repair mark-initialized --config /path/to/konsensus.toml --confirm
   konsensus start --config /path/to/konsensus.toml
   ```

   Repair writes only `NODE_INITIALIZED`; it does not recreate keys, migrate
   SQL, repair config, rebind pairing or enroll devices. Normal startup writes
   `STATE_GENERATION` and applies the pending SQL migrations. Never fabricate
   markers for missing identity material or wipe state to reopen bootstrap.
6. Inspect authenticated `/api/v1/status`: `disk_low`, `money_ready`,
   `chain_view`, `chain_sync`, `custody_mode`, storage diagnostics and
   `local_spends` where present. API availability or a successful mock startup
   does not prove Lightning readiness. Reconcile pending payments, top-ups and
   channel opens before retrying; timeouts are not proof of non-dispatch.
7. Verify the app compatibility requirements below (including scoped tokens,
   owner grants, `porch_quote_v1` and remote retry hints). A stopped pre-upgrade
   copy is a rollback option only **before the first LDK start on rc9**. After
   that, keep current state together and roll forward; never run rc7 against
   migrated SQL or restore stale Lightning state.

The executed [rc7 → rc9 upgrade check](releases/v0.3.0-rc9.md#upgrade-check)
uses the verified rc7 release sidecar (SHA-256 `e7429f6a…`) and records the
marker refusal, explicit repair, pricing adjustment and mock start. That sidecar
still generates `web_content_msat = 50`: after marker repair, rc9 refuses until
it is raised to at least 1000 or removed, because the Porch floor is validated
even when web serving is disabled. Marker repair does not change this config.
It is not a funded-wallet or live-channel migration qualification.

## rc8 → rc9 procedure

1. Stop cleanly, preserve current state, verify release provenance, and keep
   the same config/data directory. The one-host-at-a-time and pre-LDK-only
   rollback rules above apply. **No new numbered SQL migration** was added:
   the embedded set remains **001–028**. Do not interpret this as downgrade
   compatibility: local-spend, LSPS2 and owner-device state changed outside SQL.
2. A healthy rc8 installation already has `NODE_INITIALIZED`; no routine repair
   or reinitialization is needed. If the marker is absent, inspect the refusal
   and use the same consent repair only for a verified healthy identity. A
   deleted key or interrupted encrypted bootstrap needs its specific recovery,
   not a blind marker write. Check retained `web_content_msat >= 1000` as above.
3. Remove external `node.log` append/`tee` redirection before restart; node and
   LDK files now rotate (10 MiB × 5 files each by default). Journald retention
   and the security audit log remain separate. Set a supervisor stop budget
   above the initialized node's 30-second shutdown deadline (the supplied unit
   uses 45 seconds; bootstrap/password input is outside that bound).
   See [logging](operations/logging.md) and the [service example](operations/konsensus.service).
4. New capabilities remain opt-in: `--local-owner-device` on each start,
   `[lightning.lsps2_service] enabled = true`, ordinary
   `forward_to_private_channels = true`, Esplora `credentials_file`, and custom
   sync intervals. Hub LSPS2 and LSPS2 client mode cannot run together; service
   mode itself enables private forwarding. Omission does not enable a paid
   chain provider, hub, owner console, STUN or remote access.
5. Upgrade reader and serving nodes for `porch_quote_v1`; old serving nodes
   refuse before payment. Raised tariffs **do not revoke old offers**; see
   **Porch availability quotes** below. Remote clients may implement bounded
   `rate_limited` handshake hints; a hint is unauthenticated and grants nothing.
   Headless owner approvals remain local to the node host. Their files are
   owner-only, not an isolation boundary against apps under the same OS account.
6. Restart, inspect owner status and reconcile uncertain operations as in the
   rc7 procedure. Channel-open `pending_visibility` is a pending success, not
   retry permission. LSPS2's upstream pre-delivery crash window remains; its
   at-least-once metrics are not an accounting ledger. Preserve journals and
   reservations rather than deleting them to unblock funding.

## Opt-in local owner devices (rc9)

Existing console-enrolled devices can use `start --password-fd <n>
--local-owner-device` on an initialized node. Supply the flag on every launch;
there is no config migration or stored authority flag. It requires an encrypted
seed without a plaintext sibling. Existing device records without `enrolled_by`
read as `console`; the owner signature remains mandatory. Never install an
owner public key file as a replacement for startup derivation.

Without this flag, descriptor passwords keep `seed_password_not_typed` and
sidecar grants remain inactive. From rc10 (#251), local mode retains the
zeroizing owner signing key for enrollment delegated by an existing owner
device. The live mode does
not open `control.sock`, enable console grants or alter remote rules. Apps can
read `owner_device_count` to warn when only one owner device remains; the phone
must never be the only owner device. On a positively empty
directory it now enables encrypted two-phase bootstrap and one first owner
device enrollment. Legacy HTTP create/restore now write `mnemonic.enc` whenever
a startup password is present, including `--password` and `--password-file`
without local owner authority; no-password bootstrap retains plaintext behavior. This does not
automatically encrypt an existing plaintext seed. Review
[password input](operations/password-input.md), including the Mac launcher's
signing/hardened-runtime release requirement.

After a failed encrypted bootstrap commit, `/api/v1/bootstrap/state` reports
`state: "refused"`, `can_create: false`, `can_restore: false`, with no public
refusal reason or repair details. Restart for CLI diagnostics. If the crash
preceded config alignment, explicitly align `identity.mnemonic_file` to
`identity/mnemonic.enc` before live startup. Marker repair alone does not do
that, rebind an old empty-fingerprint pairing, or install a missing device
record. Recover pairing/device authority through the owner console; bootstrap
must not reopen or show the phrase again. See the
[two-phase crash rules](security/pairing.md#two-phase-local-bootstrap).

## rc7 → rc8 procedure

1. Record the installed version and config path. Stop the node cleanly; keep its
   latest state together and verify your normal backup/recovery procedure. Do
   not run `init` again or export/copy the seed as part of this upgrade. Upgrade
   one host at a time. A stopped pre-upgrade copy is only a rollback option
   **before the first LDK start on rc8**; it must never replace newer live state.
2. Verify the replacement artifact's signed checksums and release provenance as
   required by [release policy](ops/RELEASE_POLICY.md). These notes alone are not
   a release artifact or permission to publish. For source builds use Rust 1.88+
   and the release lockfile.
3. Review the config inventory below. **Esplora remains the default unless the
   owner explicitly configures `[chain] backend = "bitcoind"` or `"electrum"`.**
   Keep the selected server on the same Bitcoin network as Lightning. Neither
   backend silently falls back to Esplora. There is no automatic onboarding
   chain-source selection in this cut.
4. Remove stale `KONSENSUS_SQLITE_MIGRATIONS_DIR`, or supply the complete embedded
   SQLite set **001–028**. Check free space against the new 2 GiB default reserve.
   Keep the existing mnemonic, wallet, config, and pairing files in place. For
   encrypted seeds, arrange the interactive password or `--password-file` before
   starting the service.
5. Install rc8 and start using the same config. If a healthy legacy node refuses
   solely for missing `NODE_INITIALIZED`, use the explicit repair below. Startup
   writes `STATE_GENERATION` and applies pending migrations **020–028** before
   serving traffic. Do not delete safety markers or rewrite migration history.
6. Using your existing authenticated owner connection, inspect `/api/v1/status`:
   `disk_low`, `money_ready`, `chain_view`, `chain_sync`, `custody_mode`, and optional
   endpoint/STUN fields. A reachable API or a null diagnostic does not establish
   money readiness. Reconcile pending payments and outbox operations before
   retrying; never infer non-dispatch from a timeout or a missing fee field.
7. Update app decoders and capability checks using the compatibility section
   below, then verify ordinary reads and intended paid flows. Once LDK has
   started on rc8, preserve current state and roll forward only.

## MSRV (Rust 1.88+)

Workspace `rust-version` is **1.88** (raised from 1.75). The tree uses
`Option::is_none_or` (stabilized in 1.82), and the locked dependency set
requires Rust 1.88 (`home` 0.5.12 and related crates). Build with Rust 1.88 or
newer; CI continues to use stable. rc9 preparation uses Rust 1.91.1 for the
locked offline build, Clippy and workspace tests; this is not a fresh MSRV test.

## Missing `NODE_INITIALIZED` after upgrade (pre-#76/#77 nodes)

Nodes deployed before bootstrap (#76/#77) never wrote a `NODE_INITIALIZED` marker. After
upgrading the binary, `konsensus start` refuses with reason
`identity_without_marker` when only identity material exists, or
`identity_and_state_without_marker` when identity and wallet/channel state exist,
but the marker is absent.

This is expected for a healthy legacy installation — not a signal to wipe the data directory.
Finish the one-time marker write (the node will **not** do this automatically):

```bash
konsensus repair mark-initialized --config /path/to/konsensus.toml --confirm
```

Use the same config path you pass to `konsensus start` (`-c` / `--config`). The repair
writes `NODE_INITIALIZED` and nothing else. Normal startup still validates config
and identity and applies pending migrations; repair does not bypass those checks.

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

All nine are forward migrations; there are no shipped down migrations. Do not
run rc7 against the migrated database or drop these columns/tables to make it
start. The rollback constraints below apply to each listed migration, including
its PostgreSQL implementation; after the first rc8 LDK start, restoring an older
whole data directory is also unsafe even if SQL appears compatible.

| Ver | SQLite file | Purpose / introducing PR | State that must survive; rollback constraint |
| --- | --- | --- | --- |
| **020** | `020_pending_delivery_state.sql` | Delivery state and dispatch tracking (#103) | Preserve pending/paid dispatch evidence; no downgrade that forgets queued paid work. |
| **021** | `021_paid_delivery_rejections.sql` | Dispatch reset, retry/rejection fields, receipt acceptance backfill (#103) | Preserve paid-retry and acceptance tombstones; rc7 cannot enforce these semantics. |
| **022** | `022_receipt_bindings.sql` | Durable receipt bindings for duplicate ACKs (#103) | Do not discard receipt bindings after message retention; they prevent replay/duplicate acceptance. |
| **023** | `023_delivery_price_quotes.sql` | Durable recipient-issued quotes (#103) | Keep issued quote validity/expiry evidence through restart; do not roll back to earlier pricing state. |
| **024** | `024_outbox_operations.sql` | Exactly-once compose journal and legacy paid-row backfill (#113) | Keep operation IDs, payment identities and unresolved states; losing them can pay twice. |
| **025** | `025_outbox_recovery.sql` | Recovery accounting and compaction markers (#116) | Keep accounting/replay tombstones; do not restore older journal recovery blobs. |
| **026** | `026_outstanding_web_requests.sql` | Paid web-request reply bindings (#132) | Preserve outstanding request hashes and one-use consumption; rollback can lose or replay reply authority. |
| **027** | `027_call_state.sql` | Call state and replay lifetimes (#131) | Preserve used call IDs and pending operation reservations; downgrade loses call replay protection. |
| **028** | `028_call_request_hold.sql` | Pending request hashes and call admission holds (#131) | Keep request-bound reservations and holds; downgrade can expose unfinalized call signals. |

Files are under `crates/konsensus-storage/migrations/`. **PostgreSQL** applies
versions **020–028** through its embedded `pg_migrations()` runner. Dedicated
SQL dialect files under `migrations/postgres/` are
`021_paid_delivery_rejections.sql`, `024_outbox_operations.sql`, and
`025_outbox_recovery.sql`; 020 is inline PostgreSQL SQL, while 022–023 and
026–028 reuse the common files. `KONSENSUS_SQLITE_MIGRATIONS_DIR` affects SQLite
only; PostgreSQL does not load that directory. Migration-recovery bookkeeping
now follows the embedded PostgreSQL set (#142).

No additional numbered SQL migration landed in `5cf12a5..62238c2`. Rooms,
Browse, remote pairing bindings, paid peer exchange, fee evidence in recovery
blobs, and the generation marker still change protocol or persisted behavior;
absence of a new SQL number is not permission to downgrade.


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

## VM / multi-host upgrade rules (rc8 / rc9)

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

## Encrypted seed, password input, and custody labeling

Seed encrypt and `--password-file` shipped in #153. Custody labeling and
the remote-signer design note shipped in #154.

- Interactive `konsensus start` can prompt for the seed password. A **systemd** unit
  cannot type into that prompt. For an encrypted seed under systemd, use the opt-in
  `--password-file <path>` (regular file, mode `0600`, owner-only, **no symlink**).
  Starting this way leaves Touch ID approvals off (`seed_password_not_typed`).
- Launchers can use `init --password-fd <n>` (implies encryption) and
  `start --password-fd <n>` to hand over a password through a pipe; `0` means
  stdin. Write once, then close the writer for EOF. This avoids argv and a
  plaintext password file, and still leaves Touch ID approvals off. See
  [the handoff contract](operations/password-input.md) for limits and conflicts.
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
binary/state compatibility generation **2** (move-home journal safety). Future incompatible migrations or
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

## New config keys and changed defaults since rc7

Older binaries may reject these keys; do not reuse an rc8 config with rc7 as a
rollback workaround. Omitted opt-ins remain off. Chain backend selection also
selects embedded LDK's chain source; it does not reconfigure an external LND.

| Section | Keys / values | Default and compatibility |
| --- | --- | --- |
| Top level | `disk_free_floor_bytes` | `2147483648` (2 GiB); place before any TOML section. Zero removes the reserve, not probe-failure refusal. |
| `[chain]` Bitcoin Core | `backend = "bitcoind"`, `rpc_host`, `rpc_port`, `cookie_file`; alternatively `rpc_user` + `rpc_password_file` | Explicit opt-in; bare host + port and exactly one file-based auth mode. No inline password or credential URL. Replace the Esplora stanza rather than mixing backend keys. |
| `[chain]` Electrum | `backend = "electrum"`, `server_url`, `operator = "own"` or `"third_party"` | Server URL required; no default/discovery. `operator` defaults to `third_party`, even on loopback/LAN. `own` is the owner's declaration, not proof of validation. |
| `[remote_access]` | `listen_addr`, `advertised_endpoint` | Off unless a listener is set; then a bare advertised `host:port` is required and `[api] listen_addr` must stay loopback. Avoid API/P2P/Lightning TCP port collisions. |
| `[privacy]` | `peer_exchange = "off"` or `"paid"`, `shareable_peers`, `share_peer_labels` | Off and empty lists. Node-ID allowlists explicitly consent to sharing peers and, separately, their labels. Restart to apply; already issued quotes stay redeemable until expiry. |
| `[network]` | `advertised_addr`, `stun_server` | Optional; explicit advertised address wins. Discovery uses only owner-set STUN; no default third-party server. |
| `[calls]` | `stun_listen` | Omitted/off; optional UDP binding responder, no TURN. |
| `[pricing]` | `call_msat` | New, default `10000`, must be positive; offer kind 400 only. |
| `[pricing]` / `[web]` | Existing `web_content_msat` / `page_price_msat` | Defaults changed from 50 to 1000 msat before rc8 (#167, #173). Retained `web_content_msat < 1000` is rejected at startup, even if web serving is disabled; raise or remove it. `page_price_msat` is legacy, not a separate charge override. Porch floors still apply to advertised and paid prices. |
| `[identity]` | `hosted` | Default false; true or cloud tier reports hosted custody. Seed encryption does not turn a hosted node into a remote signer. |
| `[routing_fees]` | `minimum_msat`, `proportional_millionths`, `maximum_msat` | Defaults `5000`, `10000` (1%), `10000`; callers can tighten the computed ceiling, not widen it. Principal-only app caps may now refuse. |
| `[lightning.liquidity]` (LDK) | `enabled`, `selected_provider`, `providers` entries with `node_id`, `address`, optional `token` | Off, no providers; LSPS2 funding pilot needs explicit provider/fee consent. No automatic failover. See [liquidity](LSPS2-LIQUIDITY.md). |
| `[lightning]` test backend | `backend = "shared_mock"`, `ledger_path`, `initial_balance_msat` | New local-only shared simulated settlement ledger for integration/rehearsal; no real funds. |
| `[sponsor]` | `enabled`, `gift_sats`, `fee_sats`, `purse_sats`, `kits_per_day` | Off; defaults 20000 / 100 / 100000 sats and 2 kits per rolling day. |
| `[onboarding_subsidy]` | `max_funding_fee_rate_sat_per_vb` | Default 0 forbids new subsidized opens. The worker requests the lower of operator/invite ceilings; backends unable to enforce it (including LDK) refuse before dispatch. |

**Existing LNbits configurations:** `[lightning] backend = "lnbits"` now fails
validation/startup with `not_supported` because this integration cannot enforce
per-payment routing-fee ceilings (#99). Select an explicitly configured LDK or
LND backend through a separate wallet migration; replacing config is not a fund
transfer.

For Core, keep RPC private/authenticated; restart BitSov after cookie rotation
because LDK captures credentials at startup. Pruned Core needs enough retained
blocks for wallet catch-up; missing historical data is unavailable, not a claim
of no confirmation. Electrum requires `ssl://host:port` for public endpoints;
plaintext `tcp://` is limited to loopback/private IPs (or `localhost`). LAN
hostnames require TLS. `.onion` is rejected for both schemes: no Tor proxy is
implemented. TLS IPv6 literals are also rejected by the pinned client's parser;
use a DNS hostname for TLS. Neither backend falls back to a public explorer.
See [chain source setup and limits](CHAIN-SOURCE.md) for exact constraints.

## App API and protocol compatibility

Accept additive response fields and tolerate absent optional fields when an app
also supports rc7. Check peer capabilities before offering new wire behavior;
a node implementation is not a claim that a matching app screen has shipped.

- **Scoped-token break (#73):** tokens without an `scp` (scope) claim are
  rejected (`401`), so rc7-era sessions/tokens fail after upgrade. Re-login via
  `POST /api/v1/auth/local` or re-pairing restores only `read` + `receive`, not
  rc7's full loopback authority. With those scopes, message/compose and file
  sends, pay/keysend, channel and on-chain operations, peer administration and
  live identity routes return `403` (`token lacks required scope`). Apps that
  sent over a loopback token must pair and obtain an owner `spend` grant, or use
  the Ed25519 key-proof `POST /api/v1/auth/token`. Only that key-proof endpoint
  mints full scopes: `admin`, `identity` and `credential` are not grantable to a
  pairing, and admin and live identity routes remain unavailable to it. Discard
  cached rc7 tokens; do not keep retrying them.
- **Restore route removed (#77):** live `POST /api/v1/identity/restore` returns
  `404`. Restore exists only on the bootstrap router before identity exists.
  Move first-run restore into that bootstrap flow; live replacement uses the
  owner-control workflow described in [pairing](security/pairing.md#live-identity-replacement-binds-five-fields).
- **Mnemonic verification (#164):** `POST /api/v1/identity/verify-mnemonic`
  now returns `400` if `passphrase` is omitted while the node has a BIP-39
  passphrase configured. Prompt for and submit the recovery passphrase.
- **Upload IDs and lifetime (#83):** `POST /api/v1/files` now returns opaque
  `stage-*` IDs rather than persistent upload UUIDs. Upload staging expires after
  five minutes and is lost on restart or paired-grant expiry/revocation. Once
  claimed by a send, it is consumed even on error/cancellation. Keep local bytes
  for re-upload; do not infer permission to retry an unresolved paid send.
- **Balance (#178):** read-scoped `GET /api/v1/payments/balance` retains
  `balance_msat` unchanged and adds flat optional satoshi fields
  `onchain_spendable_sats`, `onchain_total_sats`, `anchor_reserve_sats`,
  `lightning_spendable_sats`, `closing_sats`, `contested_sats`. Absent means
  unknown, not zero; explicit zero is known. LDK supplies the breakdown;
  unsupported providers omit unknown categories. Do not sum them: anchor reserve
  is within on-chain total and closing sweeps can overlap wallet funds. Contested
  claims are conditional; Lightning spendable is outbound capacity, not a
  guaranteed routable amount. The old aggregate is not spendable Lightning.
- **Chain status (#175, #179, #180):** owner `/api/v1/status` adds
  `chain_view.{backend,trust_level,host}`. **`own_node`** labels a configured
  Bitcoin Core source or Electrum declared with `operator = "own"`; other
  Electrum sources use the default `third_party`. Only apps used with `main`
  between #175 and #179 need to replace the interim `trustless` value in enum
  comparisons; `trustless` was never on the rc7 tag. These are configured
  ownership labels, not validation, sync, privacy, or custody guarantees.
  Nullable `chain_sync` has `state: "stalled"`, `since` (Unix seconds), and
  `last_error_kind: "sync_failed"`. It records observed LDK wallet failures,
  resets on restart, and clears as failing wallets recover. Null can mean no
  observed failure or no diagnostic support; it does **not** prove readiness.
  Use `money_ready` for money readiness; the diagnostic does not itself gate it.
- **Actual routing fees (#184):** compose results (including tracked operation
  lookup), payment-status, pay and keysend responses may add **`fee_paid_msat`**.
  It is omitted unless settled outgoing LDK fee evidence is known (including all
  admission/re-admission components for a compose aggregate). Older recovery
  records or unresolved/unsupported payments may omit it. Known zero stays zero.
  `max_routing_fee_msat` remains an authorization ceiling, not an actual fee;
  do not substitute it for a missing fee, infer settlement from fees, or change
  retry/accounting authority based on this reporting field.
- **Disk guard (#169):** owner status adds `disk_low`, nullable `disk_free_bytes`
  and `disk_free_floor_bytes`. HTTP `503` / `code: "disk_low"` means the refused
  new work was not dispatched; retain existing reconciliation paths. On platforms
  without the Unix disk probe, probing fails closed; this is not a supported
  Windows-money-operations claim.
- **Readiness, pricing and exactly-once:** use `money_ready`, `readiness`,
  `api_capabilities`, freshness headers, `operation_id`, operation `state`,
  `accepted`, `retry_allowed`, and explicit `not_dispatched`/`reason` semantics.
  Confirm all-in totals (principal plus routing ceilings), including first-contact
  grants, rather than retrying on generic errors. See [fee caps](v2/ALL-IN-FEE-CAPS.md)
  and [compose operations](v2/EXACTLY-ONCE-OPERATIONS.md).
- **Rooms (#155):** `room_binding_v1` carries a fixed 2–4-node roster in encrypted
  ordinary kind-0 chat. Compose returns `member_outcomes`; history returns `room`, `room_msg` and
  `copies`. History does not provide per-member payment retry authority. No new
  room SQL table or kind is added. Fan-out is untracked; never resend a
  whole room after partial payment. Retry only proven-unpaid `refused` members,
  using the same binding/message ID and capped, journaled 1:1 legs. `settled` and
  `unknown` members are not retry permission. Existing E2EE sessions and peer
  capability are required; a room leg never buys first contact. See [Rooms](protocol/ROOMS.md).
- **Browse (#149, #167, #173):** `porch_read_v1`, `POST /api/v1/browse/fetch`
  (`node_id`, `path`, optional `max_total_msat`, `max_routing_fee_msat`) and
  `GET /api/v1/browse/cards` implement paid text/card reads. Knock/session first;
  no implicit first-contact purchase. Kinds 500/501/510 bind the response to one
  paid request; a reply never grants admission. Card cache is memory-only.
  Update app price displays to the enforced 1-sat minimum. See [Browse](protocol/BROWSE.md).
- **Peer exchange (#170):** old unpaid `PeerExchangeRequest` is refused with
  `peer_exchange_requires_quote_and_payment`; `POST /api/v1/peers/:node_id/discover`
  now returns `400` for an authorized request with a valid node ID. Its former
  `requested`/`note` success fields are gone; disable the old unpaid app flow.
  Use the signed quote + paid kind-903 redemption protocol
  only with explicit spending authority. This cut ships the receiving service,
  not an HTTP buyer workflow or automatic discovery. Off/empty owner policy
  discloses nothing. A downgrade to the former unpaid-discovery behavior would
  lose these privacy controls. See [peer exchange](protocol/PEER-EXCHANGE.md).
- **Remote access (#156):** opt-in Noise tunnel with transport-key pinning and
  single-use pairing code; persisted pairing records gain a client transport
  binding. The app must implement the framing/auth protocol and still use paired
  JWT scopes. Local token minting is unavailable through the tunnel. Preserve
  pairing/revocation state; an older binary does not implement this transport.
  See [remote access](protocol/REMOTE-ACCESS.md).
- **Front door, invites and owner scopes:** front-door cards are the profile
  surface; `front_door` scope requires an owner grant. Legacy `/api/v1/invite`
  and `/api/v1/invite/redeem` return `410` / `legacy_invite_removed` (#151);
  move to invitee-bound `/api/v1/invites` and `/api/v1/invites/accept`.
  Introduction routes remain for sponsor kits, deprecated as profile routes.
  Preserve device/owner-approval keys, pairing scope/revocation state, and
  encrypted seed configuration; older binaries cannot be assumed to read them.
- **Calls/custody:** gate mesh legs on `call_meeting_v1`; kinds 400–403 remain
  a regtest signalling prototype. Optional `stun_port`, `stun_url`,
  `peer_endpoint`, `peer_endpoint_source`, `peer_endpoint_reason` are owner status
  metadata, not automatic app settings. `custody_mode` reports `local_seed`,
  `encrypted_seed`, or `hosted_custody`; `money_signer` and `remote_signer`
  remain reserved and are not produced by configuration in this cut.

All protocol/persisted-state changes above share the migration rollback rule:
keep current payment, replay, pairing and LDK state; roll forward after the first
rc8 LDK start. Disabling a new opt-in does not undo already settled payments,
issued quotes, or persisted authorizations. This release does not provide a
reverse protocol or schema migration.


### Porch availability quotes

Upgrade both reader and serving node for `porch_quote_v1`. The node now checks
availability and the recipient's current price before any single-peer kind-500
payment, including `/api/v1/browse/fetch`. An older serving node fails closed
before payment. Content remains paid and single-use; quotes return no content.
Room compose rejects page/manifest kinds 500, 501, and 510 before payment
(HTTP 400, `porch_room`); use a single peer for these messages.

**Raising a tariff does not revoke outstanding offers.** A custom client can
pay the older kind-500 price until its offer expires: five minutes for a porch
quote, up to one hour for ordinary price offers. Timely settled payments have
up to one further hour to deliver. These offers survive restart. Safely
superseding them requires tariff/payment bindings that v1 does not store;
deleting them would also reject reads already paid before the raise. See the
[tariff-raise limitation](protocol/BROWSE.md#quote-before-payment-porch_quote_v1)
before treating a higher configured tariff as an immediate hard minimum.

Applications can call `POST /api/v1/browse/quote` with `node_id` and `path` to
preview availability, principal, and the routing ceiling. Handle HTTP 404
`porch_not_found` and the `porch_quote_unavailable`, `porch_quote_invalid`, and
`porch_unavailable` reasons as prepayment refusals. Do not auto-retry paid
failures. The safe default remains **1,000 msat = 1 sat**; explicit operator
prices at or above that floor are preserved. Lower retained values must be
raised or removed before startup. See [BROWSE.md](protocol/BROWSE.md) and
[NOTES-PORCH.md](../NOTES-PORCH.md) for compatibility and availability limits.
