# Changelog

All notable BitSov node (`konsensus`) releases are documented here. Pre-rc8 notes
also live on the corresponding GitHub pre-release pages.

## [0.3.0-rc8] — 2026-10-01 (prep; not tagged yet)

**Pre-release.** Not for production use. Source range: `v0.3.0-rc7` (`958e399`) →
`main` through **#154** (`5cf12a5`). Full narrative: [`docs/releases/v0.3.0-rc8.md`](docs/releases/v0.3.0-rc8.md).
Retained-node upgrade: [`docs/UPGRADING.md`](docs/UPGRADING.md).

**Not in this cut** (open / unmerged as of notes refresh): remote access (#156), Browse (#149), Rooms (#155).

### Identity / pairing / custody
- Touch ID device keys, owner-approval key, and optional seed encrypt (#153; reviewed stack #146 / #147 / #150).
- `konsensus start --password-file` for encrypted seed without a TTY (0600 regular file, no symlink; Touch ID approvals stay off) (#153 / #150).
- Owner `/status` reports `custody_mode`; `docs/protocol/REMOTE-SIGNER.md` design note; hosted/cloud labeled **hosted custody** (#154). `remote_signer` is reserved, not implemented.

### Network / ops
- Optional `[network] stun_server` address discovery when `advertised_addr` unset (#148).
- Relative `--config` resolves to an absolute `data_dir` (#143).
- Compose ops that fail before any payment release to `released`; restart heals stuck proven-unpaid `prepared` rows (#144).

### Payments safety
- Proven `PaymentNotDispatched` survives API conversion as `400` / `not_dispatched` across pay, keysend, open-channel, send-onchain, and related paths (#115, #117).
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
- Event-driven payment settlement cuts real-LDK first contact from ~4.2 s to ~0.55 s (#108).
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
