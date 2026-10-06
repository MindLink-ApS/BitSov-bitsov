# Changelog

All notable BitSov node (`konsensus`) releases are documented here. Pre-rc8 notes
also live on the corresponding GitHub pre-release pages.

## Unreleased

- Optional `[lightning] our_to_self_delay_blocks` (144 to 2016) sets the breach
  window peers must accept on new channels, inbound and outbound. Home nodes
  that may stay locked can set 288 (about two days). Omitting it keeps LDK's 144;
  existing channels keep their negotiated value. See [the home-node runbook](docs/operations/home-node.md#longer-breach-window-optional).

## [0.3.0-rc10] — 2026-10-06 (prep; not tagged yet)

**Pre-release.** Not for production use. Covers the 14 merged commits from
`v0.3.0-rc9` (`cd75c69`) through **#257** (`1ae4e62`), including #250
(`a0062b2`), #251 (`29385e7`), #252 (`64b4542`), #256 (`d59031f`) and #257
(`1ae4e62`).
Signing checklist: [`docs/releases/v0.3.0-rc10.md`](docs/releases/v0.3.0-rc10.md).
Upgrade steps: [UPGRADING](docs/UPGRADING.md#rc9--rc10-procedure).

### Security

- DoS edge on the unpaid peer doorway (#250). Per-IP and per-IPv6-/64
  connection and handshake token buckets, per-source and global concurrency
  caps, and bounded source tables apply before any Noise work, in both
  `whitelist` and `price_open` modes. New `[dos_edge]` table; partial tables
  inherit defaults. **`cookie_mode` now defaults to `adaptive`** (was
  `disabled`): under load, unverified sources must echo a stateless `BSc1`
  cookie before the node does DH work. Peers that cannot answer a cookie cannot
  connect while cookies are demanded. The old IPv4 /24 aggregation is removed.
  This does not make a distributed flood starvation-proof; keep upstream
  firewall/SYN protection. See [docs/operations/dos-edge.md](docs/operations/dos-edge.md).
- `scripts/release-sign.sh <tag> <commit-on-main>` does the operator's signing in
  one run: signed tag (or verify an existing one), wait for the exact-commit tag
  CI, check every draft binary against its `.sha256`, then write, sign, verify
  and attach `SHA256SUMS`/`SHA256SUMS.asc`. It never publishes. It refuses
  expired, revoked or bad signatures (#242). A non-UTF-8 locale `unbound TAG`
  abort is fixed, and the script is exercised offline in PR CI across three
  locales (#243).

### Money

- Every paid admission must carry at least **1,000 msat (1 sat)**, enforced
  after discounts and on previously issued delivery quotes. Bound web replies
  and accepted-envelope retries keep their existing handling. Older or custom
  senders paying 1–999 msat are now refused (#245, T18).
- Every advertised price (peer price tables, delivery prices and front-door
  quotes) passes the same admission floor the gate enforces, so advertised and
  enforced prices cannot drift (#248, T18b).
- First-contact prices (introduction card, front-door defaults, stateless quote)
  include `min_admission_cost_msat` when it exceeds `chat_msat`. A stranger is
  no longer refused after paying an understated quote. A zero chat price now
  quotes 1 sat instead of a free message (#253, T18c).
- **SCB restore is locked**, including preview and `--confirm`, with no bypass.
  Starting historical channel state could broadcast a revoked commitment. New
  owner-console `konsensus move-home` moves funds from a healthy node's current
  live state: cooperative close, separately consented force-close of named
  channels, and exact amount/fee sweep confirmation. Its journal
  `ldk/move-home.json` blocks normal startup until the move completes.
  **State generation rises to 2.** Whitelist sidecars are restored with
  `konsensus whitelist restore`, and export restore steps now point to
  move-home. Lightning 0.2.2 is vendored with narrow, documented patches (#246;
  #157).

### Pairing and home node

- Seed-independent X25519 box transport key (`pairing/box-transport.key`,
  0600), signed by the node identity on every unlocked start and recorded in
  `identity/identity.json`. Successful remote auth carries the proof, so
  existing clients can pin it under their trusted `node_id`. The live responder
  stays on the seed-derived static. Publishing the key needs hard links, so it
  fails on a data directory on exFAT/FAT (#244, U1).
- `start --remote-unlock`: after a reboot an encrypted home node waits for an
  existing owner-approved device over the pinned box-static Noise tunnel.
  Locked nodes serve four routes only, do not receive messages or watch
  Lightning channels, and never persist the unlock password. Wrong unlocks are
  limited per key and per process. The systemd example now runs
  `--remote-unlock --local-owner-device` instead of `--owner-control` (#247, U2).
  See [the home-node runbook](docs/operations/home-node.md).
- Owner-device delegation (#251, PR C). In `--local-owner-device`
  mode the owner signing key stays in zeroizing memory, so an enrolled owner
  device can approve another device. It signs the exact
  `bitsov-owner-delegation-v1` tuple via
  `POST /api/v1/pair/device-key/{op_id}/delegate`, and the new record shows
  `enrolled_by: "device:<approver>"`. Console `device revoke` and epoch bumps
  retire delegated keys. `GET /api/v1/pair/device-keys` adds
  `owner_device_count`; the app must keep a non-phone owner device.
- One-shot pairing tickets (#252, P1):
  `konsensus pair-ticket --config <cfg> [--qr] [--ttl 24h]` writes a file-backed
  `read+receive` ticket (TTL in `s`/`m`/`h`/`d` up to 365 days, survives
  restart, refused while locked) and prints the URI or a terminal QR only to
  the CLI's own stdout. Optional `[node] hosted_by` display label (1–64
  printable characters) appears in tickets, `/api/v1/node/lock` and
  `/api/v1/health`. It is display only and does not imply `identity.hosted`
  custody.
- Remote first run (#256, P2; merge `d59031f`):
  `start --remote-unlock --local-owner-device` on a positively empty data
  directory serves two-phase bootstrap over the box-static Noise tunnel to the
  one client that consumed a pre-bootstrap `pair-ticket`. `create-pending`
  takes a `password_commitment` and `finalize` takes the password over the
  tunnel only (`400 tunnel_required` on loopback). The commit writes only
  `mnemonic.enc`, records `enrolled_by: "remote_first_run"`, writes signed
  public identity metadata, returns the box proof, and exits 75 so
  `Restart=on-failure` restarts into locked mode for the first remote unlock.
  Legacy create/restore are not routed in this mode. See
  [remote first run](docs/security/pairing.md#remote-first-run-over-the-tunnel).
- Hub-only channels while a node can sit locked (#257; merge `1ae4e62`). For
  the whole `start --remote-unlock` run, after unlock too, new channels in
  either direction are limited to the node ids under `[lightning.liquidity]
  providers` until a watchtower exists. Other API and auto-channel opens are
  refused with `HUB_ONLY_WHILE_LOCKABLE` (API 403, `retry_allowed: false`)
  before anything is dialed or funded. Inbound requests from other peers are
  rejected before acceptance; the hub's LSPS2 JIT channels still pass. With no
  provider listed, or a non-LDK backend, every new channel is refused.
  `[lightning.lsps2_service] enabled = true` cannot start with the flag.
  Existing channels are not closed. Starts without the flag are unchanged. See
  [hub-only channels](docs/operations/home-node.md#hub-only-channels-hub_only_while_lockable).

### Docs

- Reaching a home node off the LAN over Tailscale: listeners and
  advertised addresses on the tailnet address, `[api]` on loopback, what the
  tailnet can see, and that the hub never relays for its LSP role. Port mapping
  and Tor are documented as not shipped (#254;
  [docs/operations/reachability.md](docs/operations/reachability.md)).
- rc10 release notes and signing checklist, plus an rc9 → rc10 upgrade
  procedure with every new config key and the state-generation-2 rollback rule.

### Upgrade and version

- **State generation 2:** the first rc10 node start raises `STATE_GENERATION`.
  rc9 then refuses the data directory with `state_generation_newer`. Roll
  forward only.
- No numbered SQL migration since rc9 (still **001–028**).
- `[dos_edge]` and `[node]` are new tables, and NodeConfig rejects unknown
  fields, so rc9 will not parse a config that uses them.
- Workspace version is `0.3.0-rc10` (all 13 packages).

## [0.3.0-rc9] — 2026-10-06

**Pre-release.** Not for production use. Covers all 32 merged commits from
`v0.3.0-rc8` (`f125aab`) through **#240** (`7fde729`). Full notes and the executed
upgrade check: [`docs/releases/v0.3.0-rc9.md`](docs/releases/v0.3.0-rc9.md).

### Local owner and encrypted bootstrap

- `init/start --password-fd <n>` reads a bounded, one-shot UTF-8 password from an
  inherited descriptor (`0` = stdin), with mutually exclusive password sources
  and zeroizing buffers (#232). Descriptor input alone retains
  `seed_password_not_typed`; it does not enable device approval.
- Opt-in `start --password-fd <n> --local-owner-device` derives owner authority
  at startup for existing owner-approved devices' recipient-bound spend
  envelopes (#235). Requires an encrypted seed without a plaintext sibling,
  opens no console socket, and must be supplied on every launch. Older device
  records default to `enrolled_by: "console"`; console and remote rules remain.
- Encrypted two-phase local bootstrap returns a pending phrase once, then
  requires backup-word confirmation and, in enrollment mode, P-256 possession
  plus node-signed first owner enrollment (#237). Seed, pairing and config are
  committed before `NODE_INITIALIZED`; finalize exits for an explicit restart.
  **Legacy HTTP create/restore also write `mnemonic.enc` whenever a startup
  password is present**, including flag/file input without local owner mode.
  No-password bootstrap retains plaintext behavior; existing seeds are not
  automatically converted.
- After an interrupted local-owner commit, `/api/v1/bootstrap/state` reports
  `refused` and disables create/restore even before restart (#238). Public state
  contains no disk diagnostics or repair instructions; restart CLI diagnostics
  explain the refusal. Repair remains explicit and writes only the marker.

### Lightning and funding

- Opt-in hub LSPS2 provider with opening skim, channel overprovisioning and a
  nonzero forwarding tariff (#233). Requires LDK and a private pilot token;
  off by default, mutually exclusive with the LSPS2 client. Service mode enables
  private-channel forwarding; opening fees buy liquidity, never admission.
- Durable JIT funding fee, concurrency and capital caps, bounded open retries,
  tariff retries/restart recovery and hub metrics (#236). Ambiguous dispatch
  retains reservations. **Upstream lightning-liquidity's pre-delivery crash
  window remains**; telemetry is at-least-once, not an accounting ledger.
- Owner channel opens gain `economy`/`normal`/`fast` funding priorities, preview,
  and optional whole-transaction fee caps checked before signing (#224; #190).
  Missing/stale estimates refuse; no automatic fee escalation.
- On-chain opens/sends/closes/bumps serialize and persist local-spend reservations
  through cancellation, restart, eviction and shallow reorgs (#191; #189).
  Slow funding visibility can return successful `pending_visibility`; uncertainty
  is not permission to repeat an open. Owner release requires proven absence.
- Ordinary hub forwarding into unannounced channels is opt-in via
  `forward_to_private_channels = true`, default false (#226; #225).
  Closing balances exclude unfunded channels only on proven absence (#192).

### Porch

- `porch_quote_v1` checks availability and the recipient's current price before
  single-peer kind-500 payments, including Browse (#234). Old serving nodes fail
  closed; room compose rejects kinds 500/501/510 before payment. Default
  web-content pricing remains 1 sat; valid higher configured prices remain. Retained
  values below 1000 msat must be raised or removed before startup.
- **Superseding old Porch quotes is deferred.** Raised tariffs do not revoke
  persisted offers: five-minute Porch quotes or ordinary offers up to one hour,
  with up to one further hour for delivery after timely settlement. See the
  release notes before relying on a raised tariff as a hard minimum.

### Pairing, storage and operations

- Remote pairings can request spend elevation and read first-contact quotes;
  approval/grant authority stays local (#192). Headless approvals use owner-only
  files, including device approvals and restart reissue; unavailable delivery
  returns `409 owner_approval_unavailable` (#194, #197). Paired clients can poll
  their own recipient-bound first-contact approval state (#211; #205).
- Remote handshake budgets decay and return bounded, unauthenticated retry hints
  (#214; #208); post-handshake quotas bind to the authenticated pairing and
  survive reconnects (#220; #193).
- Unreadable at-rest rows no longer fail whole lists. Preserve response bodies,
  expose diagnostic/continuation headers, refill bounded pages, and retain
  cursors across all-unreadable pages; strict item reads and backups stay strict
  (#187, #221; #186, #188).
- Chain sync has bounded independent retries, cancellation-safe ownership,
  shared Esplora rate-limit cooldowns and bounded transaction rebroadcasts;
  ghost funding is suppressed only on proven absence (#196, #200).
- Admission readiness refusals precede invoice creation; shared height caches,
  fallback on unavailable height, zero-height price rejection and sanitized
  privileged refusal codes improve readiness handling (#198, #202, #210, #218).
- Optional file-backed OAuth for an explicitly selected Esplora API, with token
  refresh, fallback, bounded timeouts/backoff and preserved upstream status
  (#215, #217; #209, #216). No paid provider is enabled by default.
- Configurable LDK Esplora sync intervals support an opt-in low-traffic profile;
  existing defaults remain 80/30/600 seconds (#223).
- Initialized-node SIGTERM/SIGINT handling uses bounded shutdown (30-second
  process deadline; excludes bootstrap/password input); service example allows
  45 seconds (#212; #206). Node and LDK logs rotate by size,
  default 10 MiB × 5 files each; remove external `node.log` redirection
  (#213; #207).
- Three-node paid regtest harness and idle-link/ghost-retry fixes (#201, #203).
  Real regtest scenarios remain separate from ordinary workspace tests.
- Regtest `hub_jit_then_stateless_admission` waits for the settled JIT channel
  capacity instead of racing the client's `revoke_and_ack`; test-only, root cause in
  [docs/qa/regtest-hub-jit-capacity-race.md](docs/qa/regtest-hub-jit-capacity-race.md) (#240).

### Upgrade and version

- Workspace and all 13 lockfile package versions: `0.3.0-rc9`.
- No new numbered SQL migrations since rc8 (still **001–028**); rc7 applies
  **020–028**. New journals/device metadata still require preserving current
  state and rolling forward after LDK starts. See [UPGRADING](docs/UPGRADING.md)
  for rc7 → rc9, rc8 → rc9 and explicit `NODE_INITIALIZED` consent repair.

## [0.3.0-rc8] — 2026-10-02

**Pre-release.** Not for production use. Source range: `v0.3.0-rc7` (`958e399`) →
`main` through **#184** (`62238c2`). Full narrative: [`docs/releases/v0.3.0-rc8.md`](docs/releases/v0.3.0-rc8.md).
Retained-node upgrade: [`docs/UPGRADING.md`](docs/UPGRADING.md).

Reuses the older release-branch draft refreshed through #154 (`5cf12a5`), then adds all
17 commits through `62238c2`. Noise remote access, Browse and Rooms are now
merged. No tag or publication is part of this preparation.

### Refresh since `5cf12a5`
- Noise-only remote app access with pinned transport keys and durable pairing bindings, opt-in (#156).
- Paid porch Browse (`porch_read_v1`), text/card serving and memory-only cache (#149); enforced 1-sat floor (#167) and matching advertised prices (#173).
- Rooms MVP (`room_binding_v1`): fixed 2–4-node roster in encrypted ordinary chat, per-member payment outcomes, no new wire kind or room table (#155).
- Owner-scoped paid peer-exchange quotes and kind-903 redemption; off by default; no unpaid discovery or automatic buyer (#170).
- Disk reserve/admission guard (2 GiB default) and `STATE_GENERATION` 1 with startup lease; not backup freshness proof (#169).
- Explicit file-authenticated Bitcoin Core chain source for chain reads and LDK (#175); explicit Electrum source and `operator` declaration (#180). No public Esplora fallback for either; `.onion` Electrum rejected (#182).
- `chain_view.trust_level`: `own_node` labels a configured Bitcoin Core / declared-own Electrum source; nullable `chain_sync` diagnoses observed LDK sync stalls, not readiness (#179). The interim `trustless` value existed only on `main` between #175 and #179, never on the rc7 tag.
- Read-scoped balance breakdown in sats alongside unchanged `balance_msat`; omitted categories mean unknown and categories may overlap (#178).
- Optional `fee_paid_msat` on payment and compose results: actual settled outgoing LDK routing fees when known; never substitute the authorization ceiling (#184).
- BIP-39 passphrase-aware mnemonic verification (#164); zeroizing mnemonic requests and seed/key material, including vendored X25519 support (#174).
- Isolated owner-token test probes (#177); argued design anchor `docs/DESIGN-REASONING.md` (#159), without treating proposals as shipped code.

### App and operator compatibility
- Tokens without an `scp` (scope) claim are rejected (`401`, #73): rc7-era sessions/tokens fail after upgrade. Re-login via `POST /api/v1/auth/local` or re-pairing restores only `read` + `receive`, not rc7's full loopback authority. With those scopes, pay/compose/file sends, channel and on-chain operations, peer administration and live identity routes return `403` (`token lacks required scope`). Sends require pairing plus an owner `spend` grant, or the Ed25519 key-proof `POST /api/v1/auth/token`; only that key-proof endpoint mints full scopes. `admin`, `identity` and `credential` are not grantable to a pairing; admin and live identity routes remain unavailable to it. Do not keep retrying a cached rc7 token.
- Live `POST /api/v1/identity/restore` is removed (`404`); restore exists only on the bootstrap router before identity exists (#77). Live replacement requires the owner-control workflow.
- `POST /api/v1/identity/verify-mnemonic` now requires `passphrase` when the node has a BIP-39 passphrase configured; omission returns `400` (#164).
- Uploaded file IDs are now temporary `stage-*` IDs, not persistent upload UUIDs (#83). Treat IDs as opaque; staging expires after five minutes, restart or paired-grant expiry/revocation, and is consumed once claimed by a send even on error/cancellation. Keep local bytes; never automatically retry an unresolved paid send.
- `POST /api/v1/peers/:node_id/discover` now returns `400` for authorized, valid-node requests; its old `requested`/`note` success fields are gone (#170). Disable unpaid discovery; this cut has no HTTP buyer replacement.
- **Esplora remains the default unless the owner configures bitcoind/electrum.** New chain keys: Core `rpc_host`, `rpc_port`, `cookie_file` or `rpc_user` + `rpc_password_file`; Electrum `server_url`, `operator` (default `third_party`). `own` is a declaration, not proven ownership or validation.
- New disk, privacy, remote-access, routing-fee, liquidity, sponsor, identity, endpoint and call config keys/defaults are inventoried in [UPGRADING](docs/UPGRADING.md#new-config-keys-and-changed-defaults-since-rc7).
- App decoders must handle `own_node`, nullable `chain_sync`, optional `fee_paid_msat`, disk/status fields, and optional balance fields `onchain_spendable_sats`, `onchain_total_sats`, `anchor_reserve_sats`, `lightning_spendable_sats`, `closing_sats`, `contested_sats`. Missing fees/balances mean unknown, not zero; null sync is not ready.
- Gate new peer flows on capabilities; preserve all-in spend caps and per-member/journal retry rules. Legacy unbound invite routes return `410` / `legacy_invite_removed`; use invitee-bound routes (#151). New node features do not establish app UI support.
- No down migrations; no rc7 binary against migrated SQL. Roll forward with latest state after the first rc8 LDK start. Preserve pairing/device/owner keys, encrypted seed config, quote/replay state and fee-recovery evidence as well as SQL. See the per-migration rollback constraints in [release notes](docs/releases/v0.3.0-rc8.md#config-api-protocol-migration-and-rollback).

### Identity / pairing / custody
- Touch ID device keys, owner-approval key, and optional seed encrypt (#153).
- `konsensus start --password-file` for encrypted seed without a TTY (0600 regular file, no symlink; Touch ID approvals stay off) (#153).
- Owner `/status` reports `custody_mode`; `docs/protocol/REMOTE-SIGNER.md` design note; hosted/cloud labeled **hosted custody** (#154). `money_signer` and `remote_signer` are reserved, not implemented.

### Network / ops
- Optional `[network] stun_server` address discovery when `advertised_addr` unset (#148).
- Relative `--config` resolves to an absolute `data_dir` (#143).
- Compose ops that fail before any payment release to `released`; restart heals stuck proven-unpaid `prepared` rows (#144).

### Payments safety
- Proven `PaymentNotDispatched` survives API conversion as `400` / `not_dispatched` across pay, keysend, open-channel, send-onchain, and related paths (#115, #117).
- LNbits configurations refuse with `not_supported` because the integration cannot enforce routing-fee ceilings (#99); LDK/LND require explicit configuration.
- Lightning spend caps cover principal **and** routing fees (#99); node-enforced paid-send caps (#80); capped re-admission refuses with a stable reason (#121).
- Quoted capped re-admission is generation-bound (#127); admission fee ceilings are reported only at wallet dispatch (#128).
- Invoice timestamps tolerate small recipient clock skew (#126).
- Incomplete paid recovery fails closed to `payment_unknown` (#119); paid resends back off while the peer is offline (#118); outbox scans are bounded and keep replay tombstones (#116).
- Paid envelopes are retained until atomic acceptance ACK (#103); channel fee/announcement requests are enforced (#101).
- Lightning circuit breaker: stabilize timing and concurrent admission — no queued call after open, no older success closing a new circuit, no older failures extending cooldown, cooldown expiry admits a single recovery probe (#112).

### Calls (regtest prototype)
- Paid 1:1 call signalling, kinds **400–403** (#131); durable call state and admission holds (migrations **027**, **028**).
- `[pricing] call_msat` (default 10 000 msat, must be > 0) prices the offer; answers / ICE / hangup keep `realtime_signal_msat`.
- Optional node STUN binding responder: `[calls] stun_listen` (UDP, **off by default**); open the port in the firewall when enabled (#136).
- Media path is WebRTC in the app; ICE uses an **owner-set** `stun:` URL (may be the node's own `stun_url` from `/status`). No TURN / no hard-coded third-party STUN.
- Mesh meetings prototype + `call_meeting_v1` (#138, #141); call/STUN follow-ups (#137).

### Web services
- Web service replies bind to the requester's paid proof (#129); outstanding paid requests persist in SQLite/Postgres (migration **026**) with expiry sweep (#132).

### Front door
- FrontDoorCard v1 with owner API and unprivileged open for Knock (#130).
- Seq floor survives corrupt cards; foreign cards ignored; verify fails closed without a Bitcoin network (#133).
- Adopted seq floor is capped so a hand-edited `u64::MAX` cannot lock publishing forever (#135).
- `front_door` scope after owner grant (#140).

### Owner / CLI / demo
- `sign-challenge` aligns with `/auth/token` owner-token challenges (#125).
- One-step owner grant with a short owner code (#145).
- One-command regtest rehearsal (#122); rehearsal **v2** adds front-door, voice-note, and 1:1 call beats (#134).
- No mock-proof profile on real backends (#123).

### Exactly-once
- Compose operations persist for exactly-once delivery (#113).
- Event-driven payment settlement reduces polling latency (#108).
- Instant paid first contact / payer-side reply acceptance (#102, #100); reconnect re-proves admission (#86).
- Pre-payment failures release proven-unpaid ops (#144).

### Readiness
- Local services stay available while Lightning recovers (BOOT-2) (#107).
- LDK startup fee fetch retries with bounded backoff (#98).
- BitSov-Data-As-Of / Data-Stale on pinned reads (#78, #79, #84); node energy (N1) and membrane events (N2) (#82, #96, #97).

### Upgrade path
- Fail closed when `KONSENSUS_SQLITE_MIGRATIONS_DIR` omits embedded migration versions (#120).
- rc7 (`958e399`) ends at **019**; rc8 adds SQLite **020–028** (#103 → 020–023; #113 → 024; #116 → 025; #132 → 026; #131 → 027–028) plus Postgres dialect files **021** / **024** / **025**. Full table: [`docs/UPGRADING.md`](docs/UPGRADING.md).
- Document `NODE_INITIALIZED` repair for pre-#76/#77 retained nodes (`konsensus repair mark-initialized`) (#120, #76/#77).
- Pairing, identity-free bootstrap, owner CLI, and scoped tokens (#72/#73, #76/#77, #92, #94).
- MSRV **1.88** (#128).
- VM upgrade: rollback only before first LDK start on the new binary; no seed copy; one VM at a time; honest hosted-custody labeling / `--password-file` for encrypted seed under systemd (see UPGRADING).

### Dependencies
- Workspace crate version set to `0.3.0-rc8` (was `0.1.0` for earlier RCs).
- `base64` 0.23.1 (#46), `mockall` 0.15.0 (#47), rust minor/patch group (#88).
- Prior rc7 TLS fix (rustls 0.23.45 / RUSTSEC-2026-0285) remains in the line of descent (#70).

### Also since rc7 (product surface)
- Budget-scoped spend grants (G1) (#81); first contact under a budget grant (#85); F1 capped first contact (#83).
- Signed introductions + capped sponsor kit (K1) (#89, #91); LSPS2 funding pilot (#87).

## Earlier pre-releases

| Tag | Notes |
| --- | --- |
| [`v0.3.0-rc7`](https://github.com/MindLink-ApS/BitSov-bitsov/releases/tag/v0.3.0-rc7) | Chain probe validates fee data; rustls 0.23.45; disclosure-key certification |
| [`v0.3.0-rc6`](https://github.com/MindLink-ApS/BitSov-bitsov/releases/tag/v0.3.0-rc6) | Non-colliding P2P port; embedded SQLite migrations |
| [`v0.3.0-rc5`](https://github.com/MindLink-ApS/BitSov-bitsov/releases/tag/v0.3.0-rc5) | Signed macOS + Windows CLI sidecars on `v*` tags |
