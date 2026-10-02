# Upgrading a retained node

This note covers common failure modes when replacing the `konsensus` binary on a
retained data directory without re-running `konsensus init`.

**rc8 preparation:** covers `main` through #184 (`62238c2`), 2026-10-02. Read
this before swapping a long-lived data directory onto the new binary. Fresh
`konsensus init` installs do not need the retained-node repair steps. For VMs, also read **VM / multi-host
upgrade rules** and **Encrypted seed / custody** below.

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
newer; CI continues to use stable. Release preparation checks the current tree
with `cargo check --workspace --offline --locked`; this is not a fresh MSRV test.

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

Seed encrypt and `--password-file` shipped in #153. Custody labeling and
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
| `[pricing]` / `[web]` | Existing `web_content_msat` / `page_price_msat` | Defaults changed from 50 to 1000 msat. Porch enforcement and advertised card/manifest/pricing surfaces have a 1000-msat floor even with lower settings or discounts (#167, #173). |
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
