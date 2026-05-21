# RELAY_PROTOCOL — Tier-2 Relay Wire Protocol

**Status:** Proposed
**Date:** 2026-05-18
**Scope:** Wire-level additions to `crates/konsensus-message/src/wire.rs` and
`crates/konsensus-node/src/session_handler.rs` enabling store-and-forward
relay service for offline thin nodes.
**Companion docs:** `docs/v2/UNIFIED_PROTOCOL.md` (UKM envelope),
`docs/v2/THREAT_MODEL_TIER2_RELAY.md` (adversarial framing — items §6.5–6.7
are normative requirements consumed by this spec),
`docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md` (operator economic surface).

## Context

A "thin node" is a BitSov peer with intermittent connectivity (a mobile
device, a laptop that sleeps, a Tier-1 light client). The Five Principles
do not bend for it: identity, payment, whitelist, sovereignty, and chain-
aware pricing apply to every UKM whether the recipient is online or not.

The Tier-2 Relay is a phagocyte: a paid, mesh-resident peer that holds
ciphertext UKMs addressed to offline recipients and delivers them on
reconnect. It is **not** the cell — the membrane is still the thin node's
Ed25519 key. The relay's role is logistical, not authoritative.

Five hard architectural commitments (all enforceable, not policy):

1. The relay never decrypts. It sees only the envelope's plaintext fields
   (sender, recipient, timestamp, payment_proof hash + amount, signature,
   nonce, ciphertext bytes — opaque to the relay).
2. Every held UKM still carries the sender→recipient `payment_proof`
   (Principle 2). Sending via a relay does not bypass the payment gate;
   the recipient verifies it on Drain.
3. Storage is its own paid service. The depositor pays the relay
   separately, priced by the chain-aware `PricingEngine`.
4. The recipient explicitly authorizes the relay (Register) and explicitly
   authorizes depositors (signed whitelist published to the relay).
   Without both, the relay refuses to hold.
5. The relay can be revoked unilaterally by the recipient with a signed
   `RelayUnregister`, and migrated to another relay with a signed
   `RelayMigrate` manifest. The relay cannot "trap" a user.

The protocol is wire-compatible with non-relay nodes via capability
negotiation; the new frames are silently ignored by nodes that do not
advertise `Capability::Relay`.

## 1. New `Frame` variants

All twelve variants are appended to the `Frame` enum in
`crates/konsensus-message/src/wire.rs`. JSON-serialized, length-prefixed
under the existing Noise tunnel — no new framing layer. Each variant is
authenticated by the Noise session (peer identity) plus, where load-
bearing, an explicit Ed25519 signature over a stable byte string.

### Relay capability and registration

**`Capability::Relay`** — a new variant of the existing `Capability` enum,
advertised in `Frame::Hello`/`HelloAck` by any node that operates a
relay service.

**`Frame::RelayChallenge { challenge: [u8; 32], expires_at: u64 }`** —
sent by the relay in response to a `RelayRegister`/`RelayMigrate`/
`RelayUnregister`/`RelayDrain`. 32-byte CSPRNG nonce + 60s expiry.

**`Frame::RelayAuth { challenge: [u8; 32], signature: Signature }`** —
Ed25519 signature over `b"BITSOV-RELAY-AUTH-V1" || relay_node_id ||
challenge || op_tag` where `op_tag` is one of
`b"REGISTER" | b"UNREGISTER" | b"MIGRATE" | b"DRAIN"`. Domain-separated.

**`Frame::RelayRegister { ttl_secs: u32, quota_bytes: u64, push_token:
Option<PushToken>, depositor_whitelist_root: [u8; 32], signed: Signature }`**

- `ttl_secs` — proposed max hold duration; capped by relay policy
- `quota_bytes` — storage ceiling per binding
- `push_token` — optional opaque wake-token (THREAT_MODEL §6.6 forbids plaintext bodies)
- `depositor_whitelist_root` — Blake3 Merkle root over recipient's depositor list
- `signed` — Ed25519 over all the above plus the latest RelayChallenge nonce

**`Frame::RelayRegisterAck { binding_id: [u8; 16], policy: RelayPolicy,
billing_msat_per_byte_day: u64, block_height: u64 }`** — relay accepts;
chain-aware pricing anchored to block height.

**`Frame::RelayUnregister { binding_id: [u8; 16], drain_first: bool,
forward_to: Option<NodeId>, signed: Signature }`** — recipient revokes.
Sovereignty-exit primitive.

### Deposit (any peer puts a message into the relay)

**`Frame::RelayDeposit { binding_recipient: NodeId, envelope:
Box<UkmEnvelope>, deposit_proof: DepositProof, ttl_secs: u32 }`**

Relay verifies: binding exists, recipient matches envelope, sender signature
valid, payment_proof preimage matches hash, deposit_proof valid (one of two),
not a duplicate, quota not exceeded, ttl ≤ policy max.

```rust
enum DepositProof {
    /// Depositor in recipient's published whitelist (Merkle inclusion proof)
    Whitelisted {
        depositor: NodeId,
        merkle_path: Vec<[u8; 32]>,
        whitelist_root: [u8; 32],
    },
    /// Depositor paid the relay separately for storage
    Prepaid {
        payment_hash: [u8; 32],
        preimage: [u8; 32],
        amount_msat: u64,
        depositor: NodeId,
    },
}
```

**`Frame::RelayDepositAck { envelope_id: MessageId, expires_at: u64,
held_bytes: u64 }`**
**`Frame::RelayDepositReject { envelope_id: MessageId, reason: String }`**

### Drain (thin node comes online and collects)

**`Frame::RelayDrain { binding_id: [u8; 16], cursor: Option<MessageId>,
max_envelopes: u32, signed: Signature }`**

**`Frame::RelayHeld { binding_id: [u8; 16], envelope: Box<UkmEnvelope>,
deposit_proof: DepositProof, deposit_received_at: u64, sequence: u64 }`** —
monotonic sequence per binding so adversarial relay cannot silently reorder.

**`Frame::RelayHeldEnd { binding_id: [u8; 16], more: bool }`**

### Acknowledge (recipient confirms; relay deletes)

**`Frame::RelayAck { binding_id: [u8; 16], envelope_ids: Vec<MessageId>,
signed: Signature }`** — Ed25519 over `b"BITSOV-RELAY-ACK-V1" ||
binding_id || blake3(concat(envelope_ids))`. Until valid Ack received,
relay holds the envelope. Re-transmissions idempotent.

### Wake-notify (optional push)

**`Frame::RelayWakeNotify { binding_id: [u8; 16], pending_count: u32,
issued_at: u64 }`** — informational hint. Push token registered in
`RelayRegister` is bridged to FCM/APNS with empty body (THREAT_MODEL §6.6).

### Migration (relay handoff)

**`Frame::RelayMigrate { binding_id: [u8; 16], target_relay: NodeId,
target_relay_addr: SocketAddr, handoff_manifest: HandoffManifest,
signed: Signature }`**

```rust
struct HandoffManifest {
    recipient: NodeId,
    new_register: RelayRegisterPayload,
    block_height: u64,
    expires_at: u64,
}
```

**`Frame::RelayMigrateAck { binding_id_old: [u8; 16],
binding_id_new: [u8; 16], accepted_envelopes: u32 }`**

### Policy (relay advertises rules)

**`Frame::RelayPolicy { max_ttl_secs: u32, max_quota_bytes: u64,
min_msat_per_byte_day: u64, allowed_kinds: BitMask<512>,
push_supported: bool, block_height: u64 }`** — sent after Hello when
Capability::Relay advertised.

### Summary table

| Frame | Direction | Auth | Purpose |
|---|---|---|---|
| `RelayPolicy` | relay→thin | Noise | Advertise terms |
| `RelayChallenge` | relay→peer | Noise | Anti-replay nonce |
| `RelayAuth` | thin→relay | Ed25519 | Prove identity |
| `RelayRegister` | thin→relay | Ed25519 | Open binding |
| `RelayRegisterAck` | relay→thin | Noise | Confirm + quote |
| `RelayUnregister` | thin→relay | Ed25519 | Close/migrate binding |
| `RelayDeposit` | peer→relay | Noise + DepositProof | Store for offline X |
| `RelayDepositAck` | relay→peer | Noise | Confirm stored |
| `RelayDepositReject` | relay→peer | Noise | Refuse with reason |
| `RelayDrain` | thin→relay | Ed25519 | Fetch held mail |
| `RelayHeld` | relay→thin | Noise | Deliver one envelope |
| `RelayHeldEnd` | relay→thin | Noise | End of batch |
| `RelayAck` | thin→relay | Ed25519 | Authorize delete |
| `RelayWakeNotify` | relay→thin | Noise | Inbox-pending hint |
| `RelayMigrate` | thin→relays | Ed25519 | Handoff manifest |
| `RelayMigrateAck` | relay→thin | Noise | Confirm handoff |

## 2. Authentication for relay registration

Reuses BitSov's Ed25519 signed-challenge pattern from invite.rs (ADR-029).
Noise session proves X25519 key; explicit Ed25519 signature provides:

- Defense in depth (future X25519/Ed25519 binding bug doesn't allow forgery)
- Auditability (recipient holds verifiable record of authorization)
- Offline construction (signed manifest replayable at target relay)

Domain-separation via `op_tag` is critical — captured REGISTER signature must
not replay as UNREGISTER.

## 3. Payment model for relay storage

**Recommendation: prepaid msat balance, debited per byte-second, priced
by the chain-aware engine.**

### Why not per-message or flat subscription

- Per-message ignores the actual cost driver (disk-time)
- Flat monthly breaks Principle 5 (revenue can't scale with chain pressure)

### Model

```
base_rate = configured_min_rate * KindCategory::Storage.multiplier()
chain_adjusted = base_rate * PricingEngine::fee_rate_adjustment()
plasticity = chain_adjusted * (1 - trust_discount(depositor))
final_rate_msat_per_byte_day = plasticity
```

**Implemented T2R2 baseline:** `PricingEngine::KindCategory::Storage` exists
as a relay service category with no direct UKM kind range. Relay settlement
queries this category directly until relay binding publications get a
collision-free UKM kind assignment.

### Settlement

- For each `RelayDeposit`: `cost_msat = ceil(envelope.size * ttl_secs *
  final_rate / 86400 / 8)`, deducted from depositor's prepaid balance.
- Insufficient → `RelayDepositReject(reason: "insufficient-prepay")`.
- Depositor opens prepay via Lightning invoice (`purpose = "relay-prepay"`).
- Recipient maintains separate prepay balance for whitelist-path deposits
  (they pay to provide free storage to friends; preserves sovereignty over cost).

### Chain-aware integration (Principle 5)

- `RelayPolicy.min_msat_per_byte_day` anchored to block_height
- `Frame::PriceTable` carries the Storage category like any other
- Fee spike → marginal storage cost rises → DoS pricing-out

## 4. Storage limits + DoS protection (six layers)

1. **Binding required**: relay refuses deposits with no `RelayRegister`-
   established binding. Eliminates "addressed to nonexistent recipient".
2. **Whitelist or prepay**: depositor produces Merkle inclusion proof OR
   Lightning prepayment.
3. **Per-recipient quotas**: `quota_bytes` is absolute ceiling.
4. **Per-depositor rate limits**: 100 deposits/min OR 10 MB/min sliding
   window per depositor NodeId.
5. **Global relay caps**: max_quota_bytes × N recipients; TTL ceiling
   (24h default); max envelopes per batch.
6. **Proof-of-payment binding**: payment_hash on envelope record; replay
   rejected.

### Outright refusals

- `Recipient::Room` or `Broadcast` envelopes (not in scope)
- Real-time signaling kinds (400-499) — stale storage harmful
- Kinds excluded by `RelayPolicy.allowed_kinds`
- Envelopes older than `now - max_ttl_secs` at deposit time
- Envelopes whose signature doesn't verify

## 5. Multi-relay routing

**Recommendation: yes, with signed `RelayBindingPublication` (kind TBD).**

```
kind=TBD  RelayBindingPublication  {
    relays: Vec<RelayEndpoint>,
    published_at: u64,
    revoked_relays: Vec<NodeId>
}

struct RelayEndpoint {
    relay_id: NodeId,
    addr: SocketAddr,
    binding_id: [u8; 16],
    fanout_rank: u8,           // 0 = primary, 1 = secondary
    accepts_kinds: BitMask<512>,
}
```

Published as payment-gated UKM to whitelist counterparties. Cached locally
by depositors. Default K=2 (primary + secondary; satisfies THREAT_MODEL §5
fanout requirement). Non-overlapping operators recommended.

At-least-once delivery; recipient deduplicates via `envelope.id`.

## 6. Migration protocol (four phases)

### Phase 1 — Authorize at source

```
thin → Relay_A: Hello → HelloAck → RelayChallenge(c1) → RelayAuth(c1, sig_over_MIGRATE)
```

### Phase 2 — Build manifest

Thin node constructs `HandoffManifest` with fresh `RelayRegisterPayload` for
`Relay_B`, signs entire manifest with Ed25519.

### Phase 3 — Pre-register at target

```
thin → Relay_B: Hello → HelloAck → RelayChallenge(c2) → RelayAuth(c2, sig_over_REGISTER)
              → RelayRegister(...) → RelayRegisterAck(binding_id_new, policy_B)
```

`Relay_B` has open binding, no held mail yet.

### Phase 4 — Handoff

```
thin → Relay_A: RelayMigrate { binding_id_old, target_relay = Relay_B,
                                target_relay_addr, handoff_manifest (signed) }

Relay_A → Relay_B: Hello (Relay_A's own identity)
Relay_A → Relay_B: RelayMigrate (forwarded with manifest)
                   Relay_B verifies signature against recipient's NodeId
Relay_A streams held envelopes to Relay_B via RelayDeposit (with relayed
                   DepositProof preserved)
Relay_B re-stores each envelope under binding_id_new
Relay_B → Relay_A: RelayMigrateAck { accepted_envelopes: N }
Relay_A → thin:    RelayMigrateAck
Relay_A deletes binding_id_old AFTER Ack received
```

### Phase 5 — Publish new binding

Thin node issues fresh `RelayBindingPublication` (kind TBD) to known peers.
Depositors update caches.

### Atomicity properties

- **Read-committed** from thin node's view
- If `Relay_A` goes offline mid-handoff: thin node holds signed manifest,
  can present directly to `Relay_B` later (`Relay_B` accepts binding but starts
  empty; `Relay_A`'s envelopes lost — same failure mode as single-relay; hence
  §5 fanout-2 recommendation)
- If `Relay_B` rejects (full, policy mismatch): `Relay_A` keeps binding live,
  thin node retries with different target

## 7. Wire-compatibility with existing nodes

**Recommendation: option (a) — capability-gated additive frames.**

### Required tweaks

1. Add `#[serde(other)]` fallback to `Capability` enum (or use `Custom(String)`
   wrapper for unknown variants). Existing nodes tolerate new variants.
2. Add `#[serde(other, rename = "_unknown")]` fallback variant `FrameUnknown`
   to `Frame` enum — current `from_bytes` errors on unknown JSON. Tolerant
   fallback is a behavior change but backwards-compatible.
3. Existing nodes don't advertise `Capability::Relay` → never selected as
   relay target → never receive relay frames in practice.
4. Existing nodes can be **served by** a relay: any peer deposits envelopes
   for them via whitelist or prepay path. Recipient uses direct delivery
   as today.

### Alternative (option b)

Coordinated version bump `Hello.version: 2 → 3`. Slower; only justified if
serde tolerance judged too risky.

## 8. Mapping to existing crates

- `crates/konsensus-message/src/wire.rs` — 16 new Frame variants, add
  `Capability::Relay`, add serde tolerance
- `crates/konsensus-message/src/transport/mod.rs` — extend `ControlEvent`
  with parallel events; new `send_relay_frame` helpers. No new trait surface.
- `crates/konsensus-node/src/session_handler.rs` — handler arms for new events
- New `crates/konsensus-node/src/relay/` module: binding_store.rs,
  deposit_validator.rs, drain_session.rs, migration.rs, policy.rs
- Relay role opt-in: `konsensus.toml: [relay].enabled = true`
- `crates/konsensus-storage/` — `RelayBinding`, `RelayHeldEnvelope` tables.
  No schema change to existing UKM tables.
- `crates/konsensus-pricing/` — `KindCategory::Storage` is available as a
  category-only storage price
- `crates/konsensus-core/src/kind.rs` — future work must assign a
  collision-free `KIND_RELAY_BINDING_PUB`; `960` is already used by
  `KIND_MLS_WELCOME`

## 9. Open questions

1. **Push provider opacity** — wake-token bridging to FCM/APNS lives outside
   the wire protocol; enforced as binary policy per operator deployment.
2. **Relay-to-relay direct topology** — assumes existing federation handshake
   works between relay peers (a relay is just a peer with Capability::Relay).
3. **Ciphertext size bucketing** — left to depositor responsibility; relay
   accepts any size up to quota.

## 10. Five-Principles audit

| Principle | How preserved |
|---|---|
| 1. Identity (relay doesn't speak as user) | `RelayHeld` carries original `UkmEnvelope` unchanged including original sender signature. Relay's NodeId distinct in Hello. `RelayWakeNotify` informational only. |
| 2. Payment gate | Original sender→recipient payment proof unchanged in held envelope. Recipient enforces gate on Drain via existing `PaymentGate::verify`. Relay storage is **separate** economic relationship. |
| 3. Whitelist | `depositor_whitelist_root` in `RelayRegister`; relay enforces inclusion proof on every `RelayDeposit` (or requires prepay). |
| 4. Data sovereignty | `RelayHeld.envelope.ciphertext` opaque to relay. Relay sees only what threat model enumerates; never the kind, never the body. |
| 5. Chain-aware pricing | Storage priced via existing `PricingEngine` with new `KindCategory::Storage`. `RelayPolicy` carries block_height anchor. Fee spikes flow through. |

## 11. Scale audit (1M users × thousands of relays)

- **Per-binding state**: ~256 bytes + envelope.size per held message.
  1M users × 2 relays = 2M bindings ≈ 512 MB across fleet — trivially shardable.
- **Per-relay capacity**: 24h TTL ceiling + 1 GB user-quota → $20/mo VPS with
  1 TB disk serves ~1000 active users.
- **Deposit throughput**: signature verify + Merkle path check + disk append +
  msat ledger update — 10K+ deposits/sec on commodity hardware.
- **Drain throughput**: bounded by network + `max_envelopes` batch cap;
  sequential streaming per binding avoids head-of-line blocking.

## 12. Cell-test summary

The relay is a phagocyte (carries) and a fat cell (stores). It is **not** the
cell. The Ed25519 identity, payment proof, ciphertext, and whitelist authority
all live on the recipient's device — the membrane is intact. Every frame in
this protocol either moves bytes the membrane already sealed, or asks the
membrane to sign a fresh authorization. The relay can refuse, lose, or migrate
but cannot impersonate, decrypt, or moderate.

## Divergences from existing build (restated)

1. `Capability` and `Frame` need `#[serde(other)]` tolerance (§7)
2. Relay binding publications need a collision-free UKM kind assignment (§5)
3. Real-time signaling kinds (THREAT_MODEL §6.7) should fold into payment-gated
   path before relay protocol ships
4. Wake-notify push-token handling is binary-level policy; wire protocol
   exposes the opaque token, not the FCM/APNS bridge

Each is marked in the body. None changes the Five Principles or trait surface.
