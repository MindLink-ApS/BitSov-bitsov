# Changelog

All notable BitSov node (`konsensus`) releases are documented here. Pre-rc8 notes
also live on the corresponding GitHub pre-release pages.

## [0.3.0-rc8] — 2026-10-02 (prep; not tagged yet)

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
- `chain_view.trust_level`: `own_node` replaces `trustless`; nullable `chain_sync` diagnoses observed LDK sync stalls, not readiness (#179).
- Read-scoped balance breakdown in sats alongside unchanged `balance_msat`; omitted categories mean unknown and categories may overlap (#178).
- Optional `fee_paid_msat` on payment and compose results: actual settled outgoing LDK routing fees when known; never substitute the authorization ceiling (#184).
- BIP-39 passphrase-aware mnemonic verification (#164); zeroizing mnemonic requests and seed/key material, including vendored X25519 support (#174).
- Isolated owner-token test probes (#177); argued design anchor `docs/DESIGN-REASONING.md` (#159), without treating proposals as shipped code.

### App and operator compatibility
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
