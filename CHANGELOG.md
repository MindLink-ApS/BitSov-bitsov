# Changelog

All notable BitSov node (`konsensus`) releases are documented here. Pre-rc8 notes
also live on the corresponding GitHub pre-release pages.

## Unreleased

### Lightning

- CLN fee-capped outgoing payments (#299): adds `xpay` and `xkeysend`/`keysend`,
  startup command discovery, local invoice validation, fresh-hash protection,
  ambiguous POST handling and a sticky overspend shutdown. Caller limits can
  only tighten routing policy. Existing preview runes must add `help` and
  payment methods. Includes mocked TLS money-path tests, Semgrep guards and
  [configuration documentation](docs/CLN.md).
- Add an opt-in [real CLN regtest](docs/regtest-e2e.md#real-cln-release-regtest-t5-t7-t8-t9)
  for settlement/payment-gate interoperability, high-fee refusal and restricted
  rune enforcement. Successful runs on both pinned CLN releases remain required
  as release evidence.

## [0.3.0-rc14] — 2026-10-09 (prep; not tagged yet)

**Pre-release.** Not for production use. Includes the seven PRs merged after
`v0.3.0-rc13` (`d625e85`): #289–#293, #295 and #297. CLN receive/read
(#297) is included at integration commit
`8644edacd9b4231ad72006605b8a6d1daf457f48`.
The [signing checklist](docs/releases/v0.3.0-rc14.md) records the scope and
merge gate. Upgrade steps, including the retained test Pi:
[UPGRADING](docs/UPGRADING.md#rc13--rc14-procedure).

### Security

- First release with spend-grant circuit breakers (#290; `f88f594`), required
  by the app's separate AI pairing work (#195). New grants default to 10 payment
  attempts per rolling minute, 60 per rolling hour, 5 consecutive failures and
  1,000 sats per rolling 10 minutes. Velocity includes the full reservation and
  fee ceiling; failed attempts do not refund rolling usage. History and limits
  are persisted atomically before dispatch, and unresolved outcomes retain
  possible failure slots across crashes. Failure pause is latched: time,
  restart, token refresh and envelope renewal cannot clear it.
- Breaker upgrade and authority boundaries (#290). Pairing file **v6 is
  forward-only**; rc13 and older nodes refuse it. Existing v2–v5 grants without
  breaker fields keep `u64::MAX` limits until explicitly replaced, including
  relation grants whose envelopes are renewed. New relation grants use the
  **fixed defaults above**, shared across their envelopes; a larger envelope
  does not raise the 1,000-sat/10-minute breaker. Console grant approval can
  choose other positive limits; zero is invalid. Only the owner console can
  run `grant-reset-breakers --client-id <id> --op <grant-op-id>`; reset preserves
  spent budget, pending reservations, expiry, payee restrictions and consumed
  payment IDs. A device intent cannot replace a live console grant. See
  [spend grants](docs/SPEND_BUDGET_GRANTS.md#circuit-breakers-n2).
- Bound LAN setup-page resource use (#292; `62d4d52`): shared per-IP read and
  POST budgets, bounded source tracking, a 2 KiB request-body limit, absolute
  five-second header/body read deadlines and a shared 32-connection cap across
  LAN listeners. Existing SAS, box approval and setup-window rules still apply.

### Node / Recovery

- Encrypted backup index (#289; `bbf9e89`). Decrypt and parse SCB metadata in
  memory with bounded framing and seed-derived v2 static-script checks. This
  is a **read-only index**, never a manager/monitor import, current-balance
  proof or permission to start old channel state.
- Owner-console `konsensus recover` (#291; `6f4ba63`). Full-tier seed restore
  into an empty directory writes an open recovery journal; normal startup
  remains fenced. Offline preview does not start LDK or contact the chain.
  Confirmed recovery requires a reachable original hub to close from its
  state, typed console consent for closure and each sweep, confirmed receipts,
  then an externally funded fresh LSPS2 channel and a settled 1-sat hub test.
  Resume the same plan after interruption and retain the new verification
  store. There is **no backup force-close fallback** for an unreachable hub;
  seed-only scanning cannot prove every old channel closed. Embedded LDK only;
  HTLCs and legacy non-v2 channel keys are outside the recovery scope.
- Recovery runbook and owner status (#295; `945eaf2`). Document R1/R2, hub trust,
  sweep consent and completion limits. Owner `GET /api/v1/status` exposes only
  read-only `recovery.state` (`absent`, `open`, `done`, `unavailable`) for LDK;
  public/non-owner callers receive no recovery state. Recovery maintenance
  serves no API and has no paired-app restore control. See
  [recovery](docs/v2/RECOVERY.md).

### Lightning

- CLN backend preview (#293; `168a271`): opt-in `backend = "cln"`, pinned-CA
  HTTPS without public roots, a restricted rune read from a mode-0600 file,
  and `getinfo` checks for CLN >= v24.11 and the configured network. This
  established connectivity and node identity; #297 adds receive/read below.
  CLN owns its wallet and backups; the BitSov mnemonic does not recover CLN funds. See [configuration](docs/CLN.md).
- CLN receive/read preview (#297; `8644eda`): adds invoice
  creation, incoming settlement verification (including keysend receipts and
  overpayment), merged payment history, channel listing and balances.
  Outgoing invoice payments and keysend still refuse before dispatch;
  **CLN cannot pay**, and payment capability / money readiness remain false.
  Reading outgoing history does not enable sending. Use a restricted rune for
  `getinfo`, `invoice`, `listinvoices`, `listpays`, `listpeerchannels` and
  `listfunds`; rotate/restart if upgrading from the getinfo-only preview.
  Stateless quotes, channel management, on-chain sends, hold invoices and
  inbound keysend TLV watching remain unsupported. Includes mocked REST
  status and payment-gate tests, credential redaction and local rustls
  transport tests; these do not replace real HTLC settlement testing.

## [0.3.0-rc13] — 2026-10-08 (prep; not tagged yet)

**Pre-release.** Not for production use. Includes all 12 PRs merged after
`v0.3.0-rc12` (`41b9e78`), through preparation tip `fc103f1`: #275–#282 and
#284–#287. The [signing checklist](docs/releases/v0.3.0-rc13.md) lists every
squash-merge commit. Upgrade steps, including the test Pi's planned fresh setup:
[UPGRADING](docs/UPGRADING.md#rc12--rc13-procedure).

### Security

- Channel admission caps and hub-only defaults (#275; `3290694`). Embedded LDK
  enforces full-capacity ceilings of 1,000,000 sats per channel and 2,000,000
  sats total by default, including accepted pending channels. Inbound,
  manual/automatic outbound and LSPS2 service admissions share atomic accounting;
  splices are refused. Configure `lightning.max_channel_capacity_sats` and
  `lightning.max_total_channel_capacity_sats` explicitly for other limits.
  Non-service LDK nodes default to configured-hub/LSP-only channels in every
  start mode; **an empty hub set refuses all new channels**. Explicit
  `lightning.hub_only_channels = false` opts out only in non-lockable modes;
  `--remote-unlock` and `--home` remain hub-only after unlock. Enabled LSPS2
  services default to unrestricted peers, with the capacity caps still applied.
  Existing channels and the separate onboarding subsidy `max_channel_sats`
  are unchanged. Owner status exposes `channel_safety`. This does not provide
  active protection while locked/offline or bound all possible losses.
- Copied-state fence (#276; `03701b5`). Bind `ldk/INSTANCE` to a random instance
  ID, host and filesystem/volume; refuse mismatches before constructing LDK.
  Existing nodes bind on their first upgraded start. Missing platform IDs fail
  closed. State generation 3 prevents older guard-aware binaries from ignoring
  the fence and open/invalid `ldk/recover.json` journals. A legitimate move of
  the latest cleanly stopped live store requires console-only `rebind-instance`
  with an exact typed challenge. **Never restore a copied data directory.**
  Same-host SD-image rollback and copies retaining both identifiers can escape
  detection; the fence is not a freshness proof. See the
  [hardware-move runbook](docs/operations/home-node.md#copied-directories-and-hardware-moves-271).
- Spend-grant payee allowlists and payment deduplication (#278; `c9d1e36`).
  Owner-approved `payee_allowlist` restricts payees independently of recipient
  budget caps; omitted/null preserves existing rules and an empty list denies
  all payees. Refusals use `budget_exceeded` / `payee_not_allowed` before dispatch.
  Invoice payment hashes and optional pay/keysend `request_id` values are
  durably deduplicated within each grant, atomically with budget reservation.
  Duplicates return `budget_exceeded` / `duplicate_payment`, without a second
  debit or dispatch; this does not replay the original result. Keysend without
  an ID remains a separate payment on each call. **Pairing schema v5 is
  forward-only**: older nodes refuse it. See [spend grants](docs/SPEND_BUDGET_GRANTS.md).
- Credential Debug redaction (#280; `9c30179`). Secret-bearing configuration
  formatters redact dedicated credentials and URLs containing userinfo, query
  parameters or fragments, including nested provider and node configuration.
- Physical claim codes and SAS enrollment (#284; `ce079c3`). A per-box code is
  created on init or empty-box setup and disclosed only through the trusted
  owner console, never an API, ticket, setup page or service journal. Preserve
  **all 18 characters: 16 random base32 characters plus 2 checksum characters**;
  never shorten the code. Four BIP-39 SAS words bind the completed Noise
  transcript, device key, fresh box nonce and claim code. Finalization requires
  the matching digest and device proof. Only one ceremony is pending, with a
  15-minute expiry and three mismatch/cancel attempts per run. Boxes with a
  claim code refuse legacy enrollment, including pre-existing legacy pending
  operations (#286); legacy initialized boxes without a code retain their flow.
- LAN-only box setup page (#286; `88bab0e`). `--home` serves a separate page
  on port 8080 with one-use QR tickets, four-word SAS comparison and box approval.
  Finalize requires that approval. The 15-minute startup window, three-cancel
  limit, private-source/Host checks, CSRF, Strict cookies and nonce-only CSP
  bound setup. Page and CLI tickets share one in-memory authority. After setup
  the page is status-only; it never handles passwords, claim codes or recovery
  phrases. **Empty-box remote first run now requires `--home`**; the old
  `--remote-unlock` flags alone are refused. Supporting app integration is
  separate from this node release.
- Signed live transport pin after first run (#287; `fc103f1`). Finalize returns
  `client_id`, `epoch`, `transport_pubkey` and `transport_signature`, alongside
  the signed box key. Clients can verify and retain the seed-derived live
  transport pin before restarting into LOCKED, then reconnect securely after
  unlock. The locked box pin and unlocked live pin are distinct; clients must
  verify identity signatures and never replace pins based on discovery alone.

### Node

- Home mode and system service (#277; `1a013b6`). `konsensus start --home`
  combines remote unlock and local owner-device authority without owner-control
  console authority. Empty-box setup exits 75 for a supervised restart into
  LOCKED; device unlock continues into UNLOCKED in the same process. Initialized
  boxes retain existing flags. Home mode conflicts with console mode and every
  startup password source. The dedicated-user
  [system unit](docs/operations/bitsov.service) forces restart on exit 75 and
  limits starts to five per 300 seconds; the older user unit allows three.
- Signed endpoint lists and optional LAN mDNS (#281; `ddf4947`). PairLink v2
  carries an ordered, identity-signed endpoint descriptor after identity exists:
  configured endpoint first, then discovered LAN and Tailscale addresses.
  Discovery uses local interfaces, not an external service. `pair-ticket --legacy`
  emits v1 for compatible legacy flows. mDNS requires **both the `mdns` build
  feature and `--home`**, configured remote access, and no explicit
  `remote_access.mdns = false`; other start modes stay silent. It advertises
  LAN discovery information, not authentication authority. New direct
  dependencies include `if-addrs` and optional `mdns-sd`; the default release
  build does not enable mDNS. See [endpoint discovery](docs/operations/home-node.md#endpoint-discovery).
- Recovery library groundwork (#282; `dbb893c`). Add `konsensus-recovery` for
  offline derivation and sweep construction for LDK v2 static `to_remote`
  outputs from a 32-byte LDK seed. It is **not wired into the node** and does
  not scan the chain or broadcast. HTLCs and v1 keys are outside its scope.
  **`konsensus recover` is not shipped**; this is not an operational recovery
  procedure or permission to restart a backup.

### CI / Docs

- Pin Semgrep to 1.179.0 (#279; `255d7bb`), avoiding the 1.180.0 installation
  failure caused by missing `semgrep-core`.
- Clarify the Linux filesystem-ID caveat and polish review nits (#285;
  `d25cdd6`): XFS/F2FS device renumbering may trip the copied-state fence on a
  legitimate live store. Consult the hardware-move runbook before rebinding.

## [0.3.0-rc12] — 2026-10-07 (prep; not tagged yet)

**Pre-release.** Not for production use. Includes all three PRs merged after
rc11 release commit `834968b`: #269 (`0425505`), #270 (`4ce5a37`) and #273
(`c5b2119`). These are the squash-merge commits in `git log 834968b..HEAD` at
preparation time; there are no two-parent merge commits in that range.
Signing checklist: [`docs/releases/v0.3.0-rc12.md`](docs/releases/v0.3.0-rc12.md).
Upgrade steps: [UPGRADING](docs/UPGRADING.md#rc11--rc12-procedure).

### Security

- Tunnel device-key enrolment (#273; squash merge `c5b2119`). Four operations
  let paired clients on the unlocked Noise tunnel request, poll and cancel
  device-key registration and list their keys. Cap pending registrations at
  eight node-wide (HTTP 429), preserving per-client limits. Approval authority
  is unchanged: console approval or owner-local delegation; delegation,
  self-revocation and other owner-management writes stay off the tunnel.
  Locked mode retains its four routes. Tests cover the route boundary and
  tunnel registration → console approval → locked restart → signed unlock.

### Money

- Home-node breach window (#269; squash merge `0425505`; v1 safety PR 1,
  building on W0/#261): embedded LDK starts with `--remote-unlock` or
  `--local-owner-device` default to 2016 blocks
  (about two weeks). Explicit `lightning.our_to_self_delay_blocks` values must
  be 288..=2016 for this profile; lower values fail startup. The enabled
  hub/LSP service role and plain non-home starts retain W0's 144-block default
  and 144..=2016 explicit range. Applies only to new channels; existing
  channels retain their negotiated delay. Peers with a lower maximum refuse
  the channel without fallback. The hub's funds can remain locked for about
  two weeks after its own force-close, which a hub/LSP may price into fees.
  See [the home-node runbook](docs/operations/home-node.md#longer-breach-window-optional).

### Node

- Node-local offline safety alert (#270; squash merge `4ce5a37`; v1 safety PR 2):
  persist an atomic synced-height heartbeat while unlocked, warn at 50% and
  report critical at 80% of each open
  channel's negotiated breach window. Owner `GET /api/v1/status` exposes
  amount-free diagnostics and retains startup alerts after catch-up; stalled
  chain observation uses an explicitly marked time estimate. No hub push.
  See [the home-node runbook](docs/operations/home-node.md#local-offline-safety-alert).

### Docs

- Update the [owner-enrollment runbook](docs/operations/home-node.md#enroll-your-first-owner-device):
  `--owner-control` requires a typed password; `--password-fd` disables owner
  device authority in that mode (#273).

## [0.3.0-rc11] — 2026-10-07 (prep; not tagged yet)

**Pre-release.** Not for production use. Includes everything since rc9
(`cd75c69`): the rc10 scope through #257, its docs/version PR #255 (`83fb6c6`),
and all eight PRs merged after `83fb6c6`, through #266 (`52670e7`).
rc10 was tagged at `83fb6c6` but never published: tag CI failed on the
pairing-ticket revocation bug fixed by #266. rc11 supersedes it.
Signing checklist: [`docs/releases/v0.3.0-rc11.md`](docs/releases/v0.3.0-rc11.md).
Upgrade steps: [UPGRADING](docs/UPGRADING.md#rc9--rc11-procedure).

### Security

- Pairing-ticket revocation fix (#266; merge `52670e7`). The cache uses a
  content digest and byte length instead of file modification time, so replacing
  a ticket revokes the old code even when timestamp and length are unchanged.
  Missing/deleted tickets invalidate the cache; unchanged tickets retain expiry
  and single-use handling. This fixes the failure that blocked rc10 publication.
- Hardening sweep (#259; merge `9a059a1`): owner front-door admission/message
  price overrides pass the admission floor; `[node] hosted_by` also rejects
  U+206A–U+206F and Unicode tag characters. Regression coverage confirms that a
  `remote_first_run` owner device counts and can approve delegated enrollment.
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

### Lightning and local watchtower staging

- Optional `[lightning] our_to_self_delay_blocks` (144 to 2016) sets the breach
  window peers must accept on new inbound, outbound and LSPS2 channels (#261,
  W0; merge `a28c84d`). Home nodes that may stay locked can set 288 (about two
  days). Omitting it keeps LDK's 144; existing channels keep their negotiated
  value. Peers may refuse a longer window. See
  [the home-node runbook](docs/operations/home-node.md#longer-breach-window-optional).
- W1 vendor hook stages durable signed `to_local` justice candidates (#262;
  merge `6bacdb0`). W1 hardening handles unsignable splice heads, corrupt-record
  quarantine, bounded pruning and replay coverage (#263; merge `f4aee2f`).
- W2a client core adds encrypted blind blobs, a durable bounded outbox and
  owner-only `GET /api/v1/tower/status` guarded/unguarded diagnostics (#264;
  merge `110bb5c`). Follow-up isolates reconciliation errors per channel and
  writes monitor mappings only when changed (#265; merge `a540c03`).
- **All W1/W2a functionality is off by default.** Omitting `[tower.clients]`
  or leaving it empty keeps staging off. Configured clients enable local LDK
  staging only: **no transport, no payments, no generated tower acknowledgments
  and no active offline protection**. Counts cover `to_local_only`, not HTLCs;
  staging cannot recover all missed historical states. The signed handoff and
  outbox are bounded, but unsigned recovery data can still grow. The hub-only
  channel restriction remains. See
  [local watchtower staging](docs/operations/home-node.md#local-watchtower-staging-w2a-optional).

### CI

- Reduce Actions minutes (#260; merge `44e3628`) with fail-closed docs-only PR
  classification, Rust dependency caching and cancellation of superseded PR
  runs. Draft PRs use the same checks as ready PRs; main and release-tag pushes
  retain full validation. No measured overall savings are claimed.

### Docs

- Reaching a home node off the LAN over Tailscale: listeners and
  advertised addresses on the tailnet address, `[api]` on loopback, what the
  tailnet can see, and that the hub never relays for its LSP role. Port mapping
  and Tor are documented as not shipped (#254;
  [docs/operations/reachability.md](docs/operations/reachability.md)).
- rc11 release notes and signing checklist, plus an rc9 → rc11 upgrade
  procedure with every new config key and the state-generation-2 rollback rule.

### Upgrade and version

- **State generation 2:** the first rc11 node start raises `STATE_GENERATION`.
  rc9 then refuses the data directory with `state_generation_newer`. Roll
  forward only.
- No numbered SQL migration since rc9 (still **001–028**).
- `[dos_edge]`, `[node]` and `[tower.clients]` are new since rc9, as is
  `[lightning] our_to_self_delay_blocks`. rc9 rejects these unknown fields.
- Workspace version is `0.3.0-rc11` (all 13 packages).

## [0.3.0-rc10] — 2026-10-06 (tagged, never published, superseded by rc11)

Tagged at `83fb6c6`, but tag CI failed on pairing-ticket revocation (#266).
No release was published. Its full scope is included in rc11 above; upgrade
from rc9 directly to rc11. The historical
[rc10 checklist](docs/releases/v0.3.0-rc10.md) is retained for reference.

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
