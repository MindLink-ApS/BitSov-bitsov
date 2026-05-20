# Tier Migration Protocol

**Status:** Proposed
**Date:** 2026-05-18
**Scope:** Migration protocol between sovereignty tiers preserving identity, channels, and history.

## 1. Overview — The Exit-ability Principle

BitSov ships four sovereignty tiers:

| Tier | Description | Node hardware | Lightning custody |
|------|-------------|---------------|-------------------|
| T0 Sovereign | User owns hardware | Home box / appliance | LDK on user device |
| T1 Self-Hosted | User owns VPS | $5 VPS | LDK on user VPS |
| T2 Relay | Phone-as-node + operator relay | User phone | LDK on phone; operator relay stores UKM only |
| T3 | Architecturally excluded | — | — |

The Five Principles forbid custodial behavior. The most load-bearing test is the **Cell Test**: a cell can migrate between tissues without losing its identity, its membrane, or its ATP reserves. If migrating from T2 to T0 loses any of those, T2 was custodial in disguise.

The hardest direction is **T2 → T0** — "I am leaving the relay." If this works without losing channels, identity, or message history, sovereignty is real. Every other migration is a simpler variant.

### Design invariants

1. **Identity is mnemonic-derived; pubkey is portable across tiers.** Ed25519 NodeId, LDK entropy seed (via `derive_ldk_entropy_seed`), and AES at-rest key all come from the same BIP-39 seed. No key form on any tier is not also derivable on every other tier.
2. **The on-the-wire pubkey never changes during migration.** Peers see the same `NodeId`. Lightning channels see the same Lightning pubkey.
3. **Channel monitor state is the only Lightning state to move.** SCB blobs (`scb_export.rs`) carry the LDK channel-manager + monitor namespaces. The pipeline is built (L5a/L5d); migration reuses it.
4. **Message history is encrypted-at-rest SQLite.** The DB file is the unit. AES-256-GCM is keyed from the mnemonic; file moves verbatim and decrypts on the new tier.
5. **Migration is opt-in and operator-non-blocking.** A T2 user does not need their relay operator's cooperation to leave — they need only their mnemonic and their SCB.

## 2. Things That Migrate

### 2.1 Identity (Ed25519 + BIP-32 + AES)
**Moves:** 24-word BIP-39 mnemonic + optional `IdentityConfig::passphrase`.
**Lives:** `IdentityConfig::mnemonic_file` (0600 permissions).
**Derived keys (do NOT migrate separately):** Ed25519 NodeId, LDK 64-byte entropy seed, SCB master AES key, at-rest AES-256 key.
**Wire-out form:** Encrypted mnemonic bundle (passphrase-wrapped) over single-use channel, OR out-of-band user transcription. NEVER plaintext over network.

### 2.2 Lightning channels (LDK channel-monitor state)
**Moves:** Contents of `<storage_dir>/ldk_node_data.sqlite` rows:
- `(primary_namespace='', secondary_namespace='', key='manager')` — channel manager
- `primary_namespace IN ('monitors', 'monitor_updates', 'archived_monitors')` — per-channel monitor state

**Form:** `BSCBKV01` blob (from `write_monitor_store_scb`), encrypted with `BSOVSCB1` AES-256-GCM wrapping from `scb_rotate.rs`, AAD `bitsov-scb-backup-v1`.
**Restore path:** `decrypt_and_load_scb_backup` in `scb_restore.rs` — already implemented.
**Counterparties:** Channels remain open with same scid; peer sees no force-close. Lightning pubkey derived from same entropy on both sides; counterparties see `channel_reestablish` from new IP, same node.

### 2.3 Whitelist + invite graph
**Moves:** SQLite rows from migrations 009 (contacts), 010 (invites_issued), 011 (accepted_invites). Plus `Peer.metadata.invite_ref` and `whitelist_source`.
**Form:** Entire encrypted SQLite database file (`konsensus.db`) moves verbatim.

### 2.4 Message history + payment proofs
**Moves:** `messages` table (every UkmEnvelope: ciphertext, signature, preimage, payment_hash, amount_msat, nonce, references). `message_plaintext` cache (migration 005). Nonce store (replay defense).
**Form:** Same SQLite DB file. **Preimages are forensic audit per Principle 2** — loss violates the principle.

### 2.5 Onboarding state
**Moves:** `OnboardingStateRecord` (migrations 012/017/018). Only meaningful mid-onboarding.

### 2.6 File storage
**Moves:** `files` table (migration 004). Encrypted blobs inline. For >2 GB stores: out-of-band signed-manifest bundle with hash committed in announcement UKM.

### 2.7 Settings / preferences
**Moves selectively:**
- `IdentityConfig` always
- `LightningConfig`, `ChainConfig`, `StorageConfig`, `NetworkConfig`: tier-specific, re-derived from target tier
- Display name + peer-display-name overrides: in `Peer.display_name` / encrypted metadata, covered by DB move
- UI-only theme: out of scope

## 3. Per-Pair Protocol

All pairs share six sub-steps: user actions, OLD node actions, NEW node actions, network view, failure modes, downtime profile.

### Shared primitives

**`konsensus migrate export`** on OLD node → produces encrypted `migration-bundle.tar.age`:
- `mnemonic.bundle` (passphrase-wrapped; or absent if user transcribes manually)
- `scb-latest.aes` (from L5a/L5d rotation, symlinked)
- `konsensus.db` (encrypted SQLite)
- `manifest.json` — schema version, source tier, source NodeId hex, blake3 of each blob, UTC timestamp
- Signed attestation over manifest by OLD node's Ed25519 key

**`konsensus migrate import --bundle <path> --target-tier <T0|T1|T2>`** on NEW node → validates manifest signature, decrypts blobs, runs `decrypt_and_load_scb_backup`, opens DB, generates tier-appropriate `konsensus.toml`.

**Migration UKM `kind=950 MigrationAnnouncement`** — signed control message broadcast to whitelist peers + operator relays. Contains: old-tier, new-tier, new-network-address (if changed), effective-at timestamp, signature.

**Dual-run validation window** — both nodes bootable, only one `active=true`. NEW boots `--shadow` mode first (validates SCB rehydration, channel set, DB integrity). Then coordinated flip: OLD → `--retiring` (refuses new sends, drains pending), NEW → active. 24h rollback window.

### 3.1 T0 ↔ T1 (the simplest pair)

**User actions**
- OLD: Settings → Migrate → choose target → enter passphrase → bundle written
- NEW: `konsensus init --tier <target>` → `konsensus migrate import --bundle ...` → passphrase

**OLD node actions**
- Final SCB rotation (`rotate_scb_backup`) for freshest channel state
- Quiesce sends; keep accepting incoming UKM into pending_deliveries
- WAL checkpoint, `VACUUM INTO` snapshot
- Pack bundle, sign manifest
- Enter `--retiring`; forward incoming UKM to NEW address until cutover

**NEW node actions**
- Verify manifest signature against claimed NodeId
- Verify blake3 of each blob
- Place `konsensus.db` at tier's storage path
- Run `decrypt_and_load_scb_backup` → boots LDK with same entropy → `list_channels()` confirms expected counterparties
- Boot `--shadow` (no outbound, no UKM sends); user confirms
- Coordinator flip: OLD → `--retired` (write-locked archive); NEW broadcasts MigrationAnnouncement
- Re-establish LDK channels via `channel_reestablish` from new IP

**Network view**
- Same NodeId. Same Lightning pubkey. New `addr` field if VPS IP differs.
- Peers auto-update `Peer.address` on receiving signed MigrationAnnouncement
- Lightning peers see `channel_reestablish` from new socket — same node, new IP. LDK handles natively.

**Failure modes + rollback**
- Bundle corruption / blake3 mismatch → NEW refuses import; OLD never `--retiring`. No state change.
- SCB rehydration fails → NEW aborts; OLD remains active.
- `--shadow` finds channel mismatch → user aborts flip; OLD remains active.
- Cutover failure mid-flip → 24h rollback window where `--retired` reverts to active. After 24h, monitor state on OLD presumed stale and LDK refuses to broadcast. **24h is mandatory.**

**Downtime**
- Online cutover: **<5 minutes** message-receive downtime (shadow validation + announcement propagation). Lightning channels never close; `channel_reestablish` resumes within seconds.
- Offline export-then-import: 1-60 minutes depending on DB size.

### 3.2 T0 ↔ T2 — User Hardware ↔ Phone + Relay (the sovereignty exit)

#### 3.2.1 T2 → T0 (the exit path)

**User actions**
1. Provision T0 hardware (`konsensus init --tier full`)
2. On phone: Settings → Sovereignty → "Leave Relay & Migrate to Home Node" → passphrase → choose transport (USB-C / local Wi-Fi / QR-stream)
3. On T0: `konsensus migrate import --bundle ... --target-tier full`
4. Confirm flip in phone UI

**OLD (phone) actions**
- Final SCB rotation
- Quiesce sends, drain pending
- VACUUM SQLite into bundle, sign manifest
- Emit signed **`RelayDeregistration` UKM (kind 951)** to every relay in `operator_hosting_contracts`. Relays mark user `Migrating`, stop accepting new UKM, continue forwarding queued UKM to new address.
- Enter `--retiring` for 24h

**NEW (T0) actions**
- Import bundle. SCB rehydrates channels (mnemonic-derived LDK keys → same Lightning pubkey)
- Counterparties see `channel_reestablish` from new IP, same node
- Broadcast `MigrationAnnouncement` (kind 950) with new T0 advertised address
- Whitelist peers update `Peer.address`. Inbound UKM routed directly to T0.

**Network view**
- Same NodeId. Same Lightning pubkey.
- Relay operators see signed `RelayDeregistration` (cannot block — user-controlled action). Obligated to forward queued UKM to new address before closing contract.
- Pubkey continuity → **no peer needs re-invitation.**

**Failure modes + rollback**
- Phone storage corruption pre-export → fall back to encrypted SCB rotation backup. Without rotation backups, phone corruption is unrecoverable — that itself is the migration failure. **L5d (encrypted SCB rotation) + analogous T2 DB rotation are mandatory prerequisites.**
- Relay refuses to forward queued UKM → degrades to message loss but not channel loss. Relay deregistration is unilateral.
- T0 box network unreachable (CGNAT) → discovered in `--shadow` mode, abort possible. If aborted, phone remains active in `--retiring` window.

**Downtime**
- **Lightning channels: zero downtime** (channel_reestablish at LDK layer, seconds)
- **Message receive: 5-30 minutes** for MigrationAnnouncement propagation
- **User-perceived offline: minutes** if phone kept running during cutover

#### 3.2.2 T0 → T2 (downsize to phone)

**User actions**
- On phone: install BitSov, "Migrate from existing node" → mnemonic → choose transport
- On T0: `konsensus migrate export --target-tier relay` → transfer to phone
- On phone: confirm import → choose relay operator(s) → relay agreement signed via `OperatorHostingContract`

**OLD (T0) actions** — same as 3.1.2 plus:
- Emit `RelayRegistration` UKM (kind 952) to each chosen operator, signed with NodeId, including new phone-advertised Lightning address + operator hosting payment proof. Operator stores via `upsert_operator_hosting_contract`.

**NEW (phone) actions**
- Import bundle. LDK boots with same entropy → same Lightning pubkey. Phone becomes the node; T0 retired after 24h.

**Network view**
- Same NodeId / Lightning pubkey.
- Peers receive MigrationAnnouncement with new advertised address (could be relay's address if phone not directly reachable).
- Lightning counterparties either keep direct channels (if phone has inbound) or relay acts as Lightning routing peer.

**Failure modes**
- Phone refuses to keep LDK live (battery, OS kills) → known T2 risk; partial mitigation via relay store-and-forward. Channels go inactive when phone sleeps; LDK auto-reestablishes when phone wakes.
- Operator refuses contract → user picks another or stays on T0.

### 3.3 T1 ↔ T2 — VPS ↔ Phone + Relay

Combinatorially same as T0↔T2 with VPS substituted for home hardware. Identical protocol; bundle format tier-agnostic; NEW node's `konsensus.toml` generated by `default_for_tier(target_tier, ...)`.

**Notable wrinkle:** T1→T2 often paired with shutting down VPS. Protocol mandates VPS remain online for 24h `--retiring` window so rollback path is real. After 24h, user free to destroy VPS.

## 4. Critical Decision Points

### A. Pubkey continuity vs key rotation

**Recommendation: SEPARATE.** Migration is hard enough. Coupling rotation to migration multiplies failure modes. Ship two operations:

1. `konsensus migrate` — moves data; identity unchanged. Pubkey continuity is default + simpler path.
2. `konsensus rotate-identity` — generates new mnemonic, signs `KeyRotation` UKM (kind 953) from old→new key, asks whitelist peers to update `Peer.node_id`, re-derives every derived key. Separate operation with own dual-run window.

Users wanting both do them in sequence: migrate first (stable identity, new tier), then rotate (separate exercise).

### B. Channel custody on T2

**Recommendation: STRICTLY mnemonic-derived.** Any divergence (e.g., "phone hot wallet" with channel keys not derivable from seed) is a **T3 trap** — user couldn't exit without operator help. Architecture must enforce that on every tier, LDK is initialized via `derive_ldk_entropy_seed(mnemonic, passphrase)`. If future UX needs ephemeral hot keys, they must be deterministically seed-derived at fixed path, and migration bundle must include path index.

**No raw key material that is not seed-derivable is permitted on any tier.**

### C. History gaps during migration window

**Recommendation: at-least-once delivery with idempotent dedup, no loss.**

Machinery already exists:
- `pending_deliveries` table migrates with DB
- Nonce store moves with DB → NEW node dedupes against any envelope id seen
- During `--retiring`, OLD forwards incoming UKM to new advertised address from MigrationAnnouncement. OLD persists forwards in `pending_deliveries` so crash mid-forward doesn't lose them.
- Relay does same store-and-forward during `RelayDeregistration` processing.

Edge case: peer sends to OLD address after MigrationAnnouncement propagated but before OLD retires — OLD still accepts and forwards. Duplicates on NEW dropped via nonce store. **Zero message loss is the contract.**

### D. Multi-relay deregistration

**Recommendation:**
1. Phone maintains `operator_hosting_contracts` (migration 013). Migration enumerates active contracts.
2. Phone sends signed `RelayDeregistration` (kind 951) to each relay in parallel. Each contains new advertised address for queue forwarding.
3. Relays Ack by transitioning `HostingContractState` to `Migrating` → `Closed` after forwarding queue (bounded: 24h deadline).
4. Unreachable relay → fire-and-forget. Queued messages may be lost for that relay only. Relay cannot prevent migration. Mitigation: UX preflight check before allowing migration.
5. Phone signs final `RelayQuorumDeregistration` (kind 954) to whitelist peers listing all deregistered relays. Peers refuse future UKM via those relays for this user — closes spoofing window.

## 5. Implementation Order

**Phase 1: T0 ↔ T1** — Lowest risk, similar tiers, no relay involved. Builds:
- `konsensus migrate export/import` CLI
- `MigrationAnnouncement` UKM kind 950
- Dual-run `--shadow`/`--retiring`/`--retired` states
- 24h rollback timer

**Phase 2: T0 ↔ T2** — Sovereignty exit. Requires relay-deregistration UKMs (951/954) + operator contract state transitions. Heavy testing of phone LDK rehydration on real iOS/Android.

**Phase 3: T1 ↔ T2** — Composition of Phase 1+2 logic. Thin shim layer.

**Cross-cutting prerequisites (ship before Phase 1):**
- Confirm SCB rotation runs on every tier (T1 and T2 must call `rotate_scb_backup` on schedule)
- Add UKM kinds 950 (MigrationAnnouncement), 951 (RelayDeregistration), 952 (RelayRegistration), 953 (KeyRotation), 954 (RelayQuorumDeregistration) to taxonomy
- SQLite migration: `node_lifecycle_state` single-row table tracking `active | shadow | retiring | retired` + 24h rollback deadline

## 6. Open Questions

1. **Mnemonic transport between devices.** T0↔T1: SSH + known-hosts pinning. T0↔T2: USB-C or local Wi-Fi with PAKE-authenticated channel. T2→T0 specifically: is QR-stream (animated QR carrying chunked encrypted bundle) acceptable for low-bandwidth/no-cable users? UX study needed.

2. **Forgotten passphrase.** Migration impossible from inside system (correctly). UX must include pre-migration "verify your mnemonic" check, refusing if user can't produce passphrase.

3. **Operator-initiated migrations.** Operator shutting down relay needs to push tenants. Is there `RelayShutdownNotice` (kind 955) operator signs with deadline? Probably yes; needs spec.

4. **Channel splice during migration.** If LDK gains splice support, migrate node while splice in flight? Likely no — require splice completion before bundle export.

5. **Large file store transfer.** >2 GB → in-band UKM impractical. Out-of-band signed-manifest blob bundle acceptable, but manifest must be committed inside UKM so move is auditable. Precise spec needed.

6. **Network address discovery for T0.** CGNAT-bound T0 box must advertise reachable address. Options: hole-punch via existing peers, optional Tor onion address, relay-assisted reachability (partially undermines T0). Separate "Reachability Tiers" doc.

7. **Backwards compatibility window.** When wire protocol changes (UKM schema, SCB blob format), how does migration handle NEW node on newer version receiving OLD-format bundle? Manifest schema version + forward-only migration of bundle formats.

8. **Audit log migration.** `audit.jsonl` not in SQLite DB. Should it move? Recommend yes — included in bundle as separate signed file, carries Principle-2 forensic value.

## 7. Five-Principles audit

| Principle | How preserved |
|---|---|
| 1. Identity | NodeId mnemonic-derived → identical on every tier. No tier-specific identity. |
| 2. Payment gate | All payment proofs migrate verbatim. New tier enforces gate on Drain. |
| 3. Whitelist | `invite_ref` + `whitelist_source` preserved via SQLite migration. Multi-relay deregistration closes spoofing window. |
| 4. Data sovereignty | Bundle is encrypted at every stage. Relays see ciphertext only during deregistration forwarding. |
| 5. Chain-aware pricing | Migration is one-shot operator action, not subject to chain-aware pricing. |

## 8. Cell-test summary

A cell migrates between tissues without losing its identity, its membrane, or its ATP reserves. Mnemonic = DNA (in nucleus). Per-tier configuration = cytoplasm composition (changes with tissue). Channels = ATP reserves (carry across). Whitelist + history = cellular memory (carries across). The 24h `--retiring` window is the cell's intercellular contact phase before it commits to the new tissue. Architectural prohibition against non-seed-derivable keys is the principle that no other organelle replicates the nucleus.
