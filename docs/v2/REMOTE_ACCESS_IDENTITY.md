# Remote-Access Identity & Authentication

**Status:** Proposed
**Date:** 2026-05-18
**Supersedes:** none (extends `auth_routes.rs`)
**Related:** ADR-029 (invite signatures), THREAT_MODEL_TIER2_RELAY.md, RELAY_PROTOCOL.md

## 0. Problem

One identity (one mnemonic), N devices (phone, laptop, desktop, tablet, friend's browser). Tier-2 Relay must verify every API call genuinely speaks for the user, without:

- Sharing the mnemonic to cloud, relay, or sibling device
- Asking for a password (Principle 1: Sovereign Identity)
- Charging Lightning per request (Principle 2 gates **messages**, not auth)
- Routing through a third-party IdP (Principle 4: no OAuth, no Supabase, no Auth0)

Identity is **mnemonic-derived Ed25519** (`konsensus-core/src/identity.rs`). Today the API has two endpoints (`konsensus-api/src/handlers/auth_routes.rs`):

- `POST /api/v1/auth/token` — sign `b"konsensus-auth"` with the node key, receive 24h JWT. Same-key only. **Does not support multi-device.**
- `POST /api/v1/auth/local` — loopback-only freebie JWT for desktop UX.

We extend, we do not replace. The Cell Test: cells signal identity via **surface receptors** derived from but not equal to nuclear DNA. Each device is a receptor.

## 1. Three-Layer Overview

| Layer | Cadence | What proves what to whom |
|-------|---------|--------------------------|
| **L1 Pairing** | Once per device lifetime (~years) | Device key authorized into user's whitelist by **primary device** (mnemonic-holder). |
| **L2 Session** | Per device boot, ≤24h TTL | Device proves whitelist membership to home node / relay, receives capability token. |
| **L3 Per-request** | Every API call | Device signs request envelope with per-device Ed25519 key; verifier checks signature + token. |

```
                                  mnemonic (DNA, on paper, in head)
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  │                       │                       │
            primary device           phone (paired)         laptop (paired)
            (mnemonic loaded)        device_key_P           device_key_L
                  │                       │                       │
                  ▼                       ▼                       ▼
        DeviceWhitelist (signed by mnemonic-Ed25519, replicated to home node + relay)
                  │
                  └── L2 challenge/response ──┐
                                              ▼
                                       relay / home node
                                              │
                                              └── L3 per-request signed envelope
```

## 2. Layer 1 — Pairing

### 2.1 Per-device keypair

Each device generates a fresh **per-device Ed25519 keypair** locally — **not** derived from the mnemonic. The mnemonic stays on at most one device at a time (the **primary device** — typically the desktop running `NodeIdentity::from_mnemonic`). All other devices hold only their own `device_key`.

```
device_key   = Ed25519 keypair, generated locally, never leaves device
device_kxkey = X25519 keypair (Noise transport), generated locally
device_id    = blake3("konsensus-v2 device-id", device_key.pub)[..16]
```

This is the **receptor**, not the DNA. Loss of a device cannot leak the mnemonic. Compromise leaks only that device's authority — revocable in L1.

### 2.2 The DeviceAttestation envelope

When user pairs a new device, primary device signs `DeviceAttestation` with mnemonic-derived Ed25519 key (`NodeIdentity::ed25519_signing_key`). This is the single load-bearing use of the mnemonic key for auth — everything else is per-device.

```rust
// konsensus-core/src/device_attestation.rs (new)
#[derive(Serialize, Deserialize)]
pub struct UnsignedDeviceAttestation {
    pub version: u8,                       // 1
    pub identity_pubkey: [u8; 32],         // mnemonic-derived Ed25519 (NodeId)
    pub device_pubkey:   [u8; 32],         // per-device Ed25519
    pub device_kx_pubkey:[u8; 32],         // per-device X25519
    pub device_id:       [u8; 16],
    pub device_label:    String,           // "Maya's iPhone"
    pub device_kind:     DeviceKind,       // Mobile | Desktop | Browser | Tablet | Headless
    pub issued_at_unix:  u64,
    pub expires_at_unix: u64,              // recommended: issued + 2 years
    pub capabilities:    Caps,             // read, write, payment, admin-revoke
    pub nonce:           [u8; 16],
}

#[derive(Serialize, Deserialize)]
pub struct DeviceAttestation {
    pub unsigned: UnsignedDeviceAttestation,
    pub signature: [u8; 64],   // Ed25519 by identity_pubkey over
                               // blake3("bitsov-device-attest/v1\0" || canonical(unsigned))
}
```

Domain-separation prefix `bitsov-device-attest/v1\0` mirrors `BITSOV_INVITE_DOMAIN_V2` from `invite.rs` (ADR-029).

### 2.3 Pairing wire flow

```
Primary device (D_p, has mnemonic)        New device (D_n)
─────────────────────────────────         ──────────────────
                                          1. generate device_key, device_kxkey
                                          2. display QR with PairingRequest:
                                             { device_pubkey, device_kx_pubkey,
                                               device_label, ephemeral_nonce }
3. scan QR
4. user sees confirm screen (label, kind, caps)
5. user taps "approve"
6. construct DeviceAttestation, sign with mnemonic-Ed25519
7. push to home node's DeviceWhitelist AND send to D_n over Noise_XX
                                          8. D_n stores attestation locally;
                                             persists device_key in OS keystore
                                             (Keychain / Keystore / WebAuthn)
                                          9. D_n proceeds to L2
```

**Transport options (ranked):**

1. **QR + Noise_XX over local mDNS** when co-located (preferred, zero relay dependency). Reuses existing `noise.rs`.
2. **QR + Noise_XX tunneled through home node** when not co-located.
3. **Air-gap export**: primary displays attestation as second QR (or printable 24-word backup of attestation). D_n scans. Survives offline pairing.

**No OAuth / no email magic links / no SMS.** Sovereignty.

### 2.4 Lightning at pairing — optional anti-Sybil binding

The user's instinct ("Lightning transaction from a whitelisted pubkey") is **not** needed for cryptographic authentication — Ed25519 signature suffices. But it has legitimate use: **anti-Sybil at relay onboarding**.

Recommendation: at **first pairing to a new relay**, the user's home node issues a 1-sat keysend to the relay's pubkey, with TLV payload binding the keysend to `(identity_pubkey, device_pubkey, issued_at)`. Relay records this as one-shot proof-of-funds. Future devices paired to **same** identity inherit this anchor — no per-device keysend.

This is **not** auth (auth is the Ed25519 signature). It is admission policy. Relay operator may waive for known whitelisted identities.

## 3. Layer 2 — Session Establishment

### 3.1 Wire flow

```
Device (D)                                Relay (R) or Home node (H)
─────────────                              ────────────────────────────
1. GET /api/v1/auth/challenge
                                          2. issue ChallengeBlob:
                                               { server_nonce: 32 bytes,
                                                 issued_at, expires (30s),
                                                 audience: "relay-<scid>",
                                                 audit_id: uuid }
3. read challenge
4. construct SessionRequest:
     { device_attestation,                (full L1 envelope)
       challenge: ChallengeBlob,
       device_signature:                  (Ed25519 over blake3(
                                              "bitsov-l2-session/v1\0"
                                              || canonical))
     }
5. POST /api/v1/auth/session
                                          6. server validates:
                                             (a) attestation.signature ✓ by identity_pubkey
                                             (b) device_signature ✓ by attestation.device_pubkey
                                             (c) challenge not expired, audience matches, audit_id unused
                                             (d) (relay) identity_pubkey on accepted-tenants list
                                             (e) (relay) DeviceWhitelist for identity hasn't revoked device_id
                                             (f) issue capability token (§3.2)
                                          7. return SessionResponse:
                                               { capability_token, expires_at }
```

### 3.2 Token choice — biscuit, not plain JWT

Existing JWT in `auth.rs` is HMAC-signed by `derive_jwt_secret()` (per-node secret) — fine for single-key local auth. But for multi-device + attenuable capabilities (read-only browser session, write desktop, payment-capable phone) **JWT is wrong tool**. JWTs concatenate; they do not attenuate cryptographically.

**Recommendation: biscuit-auth** (Rust crate `biscuit-auth`, Apache 2.0, mature, no exotic crypto). Properties:

- **Attenuable**: desktop with full capability hands browser session a view-only biscuit by appending restrictive caveat block. Browser cannot remove caveat — only further restrict.
- **Offline-verifiable**: signed by home node's Ed25519 key. Relay verifies without contacting home node. (HMAC JWTs require shared secret — doesn't scale to multi-relay.)
- **Self-contained policy**: caveats encode `device_id`, `capabilities`, `exp`, `audience` directly. No DB lookup.

Biscuit root key = home node's mnemonic-derived Ed25519 key (`NodeIdentity::ed25519_signing_key`). Relays carry home node's pubkey from federation gossip envelope.

If `biscuit-auth` is too heavy: fall back to **paseto v4.public** (Ed25519, simpler, no attenuation but adequate). Do **not** stay on HMAC JWT for multi-device.

```
biscuit facts (per device session):
  identity("0dc012...")           // hex of identity_pubkey
  device("a3f9...")               // hex of device_pubkey
  device_id("4c8a...e1")          // hex of device_id
  caps(["read","write"])          // strings; "payment" gated separately
  audience("relay-1040393086621843457")
  iat(1747171200)
  exp(1747257600)                 // iat + 86_400
```

### 3.3 Session lifetime

- Default TTL: **24h** (matches existing JWT cadence)
- Refresh: device sends fresh `SessionRequest` near expiry. **No long-lived refresh tokens.** Attestation in OS keystore is the refresh token — doesn't expire for years; revoking it (§5) revokes everything.
- Browser sessions: **2h** default, configurable down to **15min**, attenuated by issuing desktop.

## 4. Layer 3 — Per-Request Auth

### 4.1 Signed envelope

Every API request carries two headers:

```
Authorization: Biscuit <base64url-biscuit>
X-BitSov-Signature: <base64url-ed25519-sig>;ts=<unix>;nonce=<hex16>
```

Server-side validation:

```rust
let sigtext = blake3::keyed_hash(
    b"bitsov-l3-req/v1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",       // 32-byte key
    &[
        method.as_bytes(),       // "GET", "POST", ...
        b"\n",
        path.as_bytes(),         // "/api/v1/messages/send"
        b"\n",
        ts_bytes,                // 8-byte BE u64
        b"\n",
        nonce_bytes,             // 16 bytes
        b"\n",
        body_hash,               // blake3(body) — 32 bytes
        b"\n",
        biscuit_id,              // biscuit's revocation_id — 16 bytes
    ].concat(),
);
verify(device_pubkey_from_biscuit, sigtext, sig)?;
```

- **Timestamp window**: ±60s
- **Nonce**: 16 random bytes; relay stores `(biscuit_id, nonce, ts)` in small LRU keyed by `device_id` for replay protection. 5000 entries × 1M users × 3% concurrently active ≈ 150M entries cluster-wide. Each relay sees only its own tenants — back-of-envelope ~1.5M entries per relay, trivial.

### 4.2 No body, no signature surface

GETs with no body still sign `body_hash = blake3(b"")`. This catches `/api/v1/messages/list` replay across users — path is part of signed surface; swapping biscuit but reusing signature fails.

### 4.3 Cost

One Ed25519 verify (~50µs) + one biscuit verify (~80µs) + one HashMap lookup. At 10k req/s per relay → ~1.5% of one core. Cheap. **No Lightning fee per request — payment gates messages, not bytes.**

## 5. Critical Decisions

### A. Device whitelist storage — **CRDT replicated to user's own nodes; relay holds ciphertext only**

The whitelist is small append-only log of `DeviceAttestation` + `DeviceRevocation` records, ordered by `(issued_at, hash)`, replicated via existing UKM envelope plumbing.

- **Primary copy:** user's home node(s) hold canonical state
- **Relay copy:** stores log as **opaque AES-256-GCM ciphertext** keyed by `NodeIdentity::aes_key()` of the user. Relay cannot read; only confirms "signature came from key the user's biscuit-root authorized" — proven by biscuit, not whitelist.
- **No on-chain storage** — Bitcoin OP_RETURN doesn't scale to 5M devices × N revocations. Reserve chain for genuine timestamp anchors (identity birth certificate — §C).
- **No "primary must be online":** attestation is self-verifying offline. Primary only needed when **adding** or **revoking**.

Matches Cell Test (DNA in nucleus = whitelist in home nodes; receptors on surface = attestations on devices); scales (~5 KB ciphertext per tenant); no third party; sovereignty-preserving (relay can't enumerate user's devices).

### B. Device revocation — **Mnemonic-signed `DeviceRevocation` + short-TTL session caching**

Maya loses phone:

1. From any mnemonic-holding device (laptop), Maya signs:
   ```
   DeviceRevocation {
       version: 1,
       identity_pubkey,
       revoked_device_id,
       revoked_at_unix,
       reason: Lost | Compromised | Rotated | Decommissioned,
       nonce,
       signature: Ed25519 by mnemonic key
   }
   ```
2. Appended to DeviceWhitelist log, gossiped to all relays via federation envelope.
3. **Fail-safe:** L2 tokens have 24h TTL → lost phone's biscuit auto-dies within 24h even if revocation gossip doesn't reach all relays.
4. **Faster revocation:** each relay maintains `revoked_device_ids` set (~16 bytes × 5 revocations × 1M users = 80 MB per relay, trivial). L3 verifier checks set; revoked `device_id` rejected immediately.

**Not chosen:**
- "Time-out + reauth only" — too slow for stolen device
- "Bitcoin-anchored revocation list" — doesn't scale; no security gain over Ed25519

**Why mnemonic-signed not device-quorum-signed:** quorum schemes ("any 2 of 3 paired devices revoke a 4th") add UX complexity that breaks single-device users. Mnemonic is the floor. Future ADR can add quorum revocation as **additional** path; do not make it the only path.

### C. Mnemonic recovery — **Identity birth certificate + relay re-registration**

Maya loses every device, has only 24 words.

1. Install BitSov on new device
2. Enter mnemonic. App calls `NodeIdentity::from_mnemonic`. Mnemonic re-derives **same** `identity_pubkey`.
3. Generate **new** per-device keypair. Self-sign `DeviceAttestation` (first device of new whitelist generation).
4. **Catch:** relays have **old** whitelist generation cached. They'll reject new device because `device_pubkey` isn't in cache.

**Solution: identity birth certificate + generation counter.**

- Every identity has `birth_cert`: `{ identity_pubkey, generation: u64, issued_at, signature_by_mnemonic_key }`. Generation increments **only on mnemonic recovery** (legitimately wipes whitelist). New generation invalidates **all** prior attestations + revocations under that identity.
- birth_cert anchored lazily in **federation gossip envelope** (not on-chain — too slow for recovery). Relays accept higher-generation birth_cert from legitimate mnemonic.
- After recovery: walk relay re-onboarding once per relay (one Lightning keysend, §2.4). Past **channels** recovered via LDK's `keys_manager` + same mnemonic — already in L5d recovery drill. **Channel recovery and identity recovery share mnemonic; don't need to share recovery flow.**
- **Bitcoin anchor (optional, future ADR):** publish `blake3(birth_cert)` in OP_RETURN at generation creation. Relays refuse generation bump unless seeing anchor in confirmed Bitcoin tx ≥ N blocks deep. Defeats "attacker stole mnemonic, rotates whitelist faster than user reacts" — gives user window to publish own anchor first. **Do not require for v2; design field, leave optional.**

### D. Pairing without prior contact (new user) — **Layer 0: install ⇒ generate**

Lisa has no BitSov identity. Cannot accept Maya's invite via L1 (requires primary with mnemonic).

**Layer 0 (one-time, before L1 exists):**

1. Lisa installs BitSov on phone
2. App generates **fresh 24-word mnemonic** (`NodeIdentity::generate`). Phone IS primary device.
3. App calls `from_mnemonic`, derives identity_pubkey, generates `device_key`, self-signs **first** DeviceAttestation, writes birth_cert (generation 0).
4. **Mandatory backup gate**: until user has (a) written down 24 words or (b) printed steel/paper backup, app gates write capability. Maya's invite accepted, but Lisa cannot accept payment downgrade or revoke anything until backup confirmed.

Lisa's phone is BOTH mnemonic-holder AND paired device. Subsequent devices (laptop, tablet) follow normal L1 with phone as primary.

This is existing `NodeIdentity::generate` formalized. No new crypto. Novelty: **mandatory-backup gate** before user participates in payment-flow operations.

### E. Borrowed-browser at friend's house — **Yes, via primary-device-issued ephemeral biscuit OR mnemonic entry**

Maya, no phone, no laptop, friend's browser. 15 minutes of email needed.

**Flow:**

1. Open `https://node-alice.example` in friend's browser. Static page from home node asks: "Trusted or borrowed device?" -> "borrowed"
2. Page generates **ephemeral browser device_key in-memory** (Web Crypto API, non-extractable). Displays 9-digit pairing code + QR.
3. Maya needs to pair from another device... but she has none.

**Principled answer: borrowed-browser session requires EITHER (a) one paired device OR (b) the mnemonic.**

If Maya has mnemonic memorized: she may enter directly in friend's browser to derive identity, generate **short-lived (15min, read-only) biscuit**, and go. **Deliberate sovereignty trade-off**: typing mnemonic into foreign device is risky and **should be explicit opt-in**, with screen saying "this device may keylog your mnemonic — rotate to new mnemonic within 24h if you do this." Rotate action is recovery flow §C.

If she has neither mnemonic nor paired device: **cannot access BitSov.** Correct. Sovereignty means user is bottleneck when user has surrendered all key material. There is no "forgot password" because there is no password.

**Design implication:** borrowed-browser flow MUST require mnemonic each time — never cache, never localStorage, never `navigator.credentials`. WebAuthn is **not** substitute (doesn't derive mnemonic, only binds to hardware key friend's machine doesn't have).

**UX recommendation:** discourage in UI. Show: "You're about to enter your master phrase on a device you don't control. Don't. Use trusted device. If you have to, plan to rotate your identity afterward." Then let her continue. Sovereignty includes the right to make your own mistakes.

### F. Lightning payment as identity proof — **Once per relay, never per request, never per session**

| Event | LN payment? | Why |
|-------|-------------|-----|
| L1 — pairing new device | **No** | Signature sufficient. LN here would block legitimate user mid-pairing if channel closed. |
| L2 — establishing session | **No** | 5M LN payments/day to log in × 1M users × 5 devices. Breaks Lightning UX. |
| L3 — per request | **Never** | Explicit Principle-2 boundary: payment gates **messages**, not authentication. |
| First connection to new relay | **Yes — one 1-sat keysend** | Anti-Sybil + ties identity to Bitcoin-spendable key. Relay's policy. |
| Recovery from mnemonic | **No for identity, yes for channels** | Identity recovery is signature-only. Channel recovery uses BIP-32 LDK paths (separate flow, L5d). |
| Generation bump | **Not required, recommended OP_RETURN anchor** | See §C. |
| Borrowed-browser | **No** | Cost is typing mnemonic, not sats. |

**One sentence:** Lightning gates messages and bootstraps anti-Sybil at relay admission. Lightning does **not** authenticate.

## 6. Threat Model

| Attacker capability | Layer broken | Cost / defense |
|---------------------|--------------|----------------|
| Steal mnemonic | All | Game over. Same as Signal phone-number compromise, except user can rotate generation. **Defense:** mandatory backup gate; hardware-mnemonic option (Coldcard-style) future ADR. |
| Steal one device + key material | L2 + L3 for that device only | Window = revocation propagation (≤24h worst, 1 gossip round best). **Defense:** L1 revocation list pushed to all relays. |
| Steal relay operator's keys | Relay forges L2 biscuits *for users who trusted that relay only* | Home node is biscuit root-of-trust. Relay can downgrade availability but cannot impersonate user to other relays. **Defense:** user signs biscuit's root pubkey themselves; relays cache only. |
| Compromise home node | All layers, this user only | Identity fully owned by user. **Defense:** home node IS user's sovereignty — same trust profile as laptop holding PGP key. |
| Network MITM | L1 (during attestation transfer) | **Defense:** Noise_XX between primary and new device; QR carries device_pubkey verifying out-of-band. |
| Replay old L3 request | One API call | **Defense:** (timestamp, nonce, body_hash) signed; nonce LRU on relay. |
| Replay old L2 biscuit | One day of access | **Defense:** 24h exp + revocation list. |
| Side-channel timing on Ed25519 | The mnemonic key | **Defense:** `ed25519-dalek` constant-time impl, already in use. |
| FCM/APNS observing push payloads | User's online signal | **Out of scope here** — see THREAT_MODEL_TIER2_RELAY.md §2.11. Auth layer doesn't send push. |

**To impersonate Maya at relay**: attacker needs **either** (a) Maya's mnemonic, **or** (b) non-revoked Maya-issued attestation AND its corresponding device key. Both explicit user-held secrets. No phone number, no email, no SaaS pwn-and-takeover path.

## 7. UX Implications

| Layer | User experience |
|-------|-----------------|
| **L1 first time** | Install BitSov, see mnemonic, confirm backup, done. ~90s. Same as Bitcoin wallet. |
| **L1 add device** | On primary: tap "Add device", show QR. On new device: scan QR, confirm label & permissions. ~30s. |
| **L1 remove device** | On any primary: device list, tap "remove", confirm. ~10s. |
| **L2** | Invisible. App boots, calls /auth/session, gets token. ~150ms over fast network. |
| **L3** | Completely invisible. Built into HTTP client. |
| **Borrowed browser** | Type mnemonic with giant warning. Session capped at 15min, read-only by default. |
| **Mnemonic recovery** | Walk through write-down → re-enter mnemonic → wait for re-onboarding to each relay. Each shows "Welcome back" + 1 sat keysend. ~2min total. |

The user **never** sees: password field, email field, OAuth provider, CAPTCHA, "verify your phone" SMS, TOTP setup, "magic link sent" page. They see device names and mnemonic backup. That's it.

## 8. Integration with Existing Endpoints

`POST /api/v1/auth/local` (loopback freebie) — **unchanged.** Stays in for desktop UX. Desktop client on 127.0.0.1 is already inside trust boundary; making it do L1/L2/L3 would be ceremony for no gain.

`POST /api/v1/auth/token` (signature challenge) — **deprecate, alias to L2.** Convert into L1 self-attestation flow for single-device mnemonic-holding nodes. Same wire shape: signed challenge in, JWT out. New optional fields (`device_attestation`, `device_signature`) trigger L2 biscuit path; absence preserves backward compatibility.

**New endpoints:**

```
POST /api/v1/auth/device/attest           # L1, primary-device signs
POST /api/v1/auth/device/pair             # L1, new-device pairing initiation
GET  /api/v1/auth/device/list             # L1, list whitelist (requires write biscuit)
POST /api/v1/auth/device/revoke           # L1, mnemonic-signed revocation
POST /api/v1/auth/identity/generation     # C, bump generation (recovery)
GET  /api/v1/auth/challenge               # L2, server nonce
POST /api/v1/auth/session                 # L2, attestation + signed challenge → biscuit
```

Existing `AuthUser` extractor gains sibling `AuthDevice { identity: NodeId, device_id: [u8;16], capabilities: Caps }` from biscuit. Handlers ask for more specific type when they need per-device granularity (e.g. `/api/v1/payments/send` requires `caps.payment`).

`AuthUser` continues via compatibility shim: biscuit-authenticated request synthesizes `AuthUser` with `node_id = identity_pubkey_hex`. **Every existing handler keeps compiling.**

## 9. Scale Check

| Quantity | Per-user | At 1M users × 5 devices |
|----------|----------|-------------------------|
| DeviceAttestation size | ~300 B | 1.5 GB total replicated. Per relay cache: ~50 MB. |
| Revocations (2% lifetime churn) | ~6 B amortized | ~30 MB per relay. |
| Biscuit size | ~400 B | Not stored — issued and discarded. |
| Per-request signing overhead | 50µs Ed25519 verify | ~1.5% of one core at 10k req/s. |
| Per-request nonce LRU | 16 B × 5k × 5 devices | ~400 KB per user per relay; ~2 GB per relay at 5k tenant ceiling. Fits in RAM. |
| Pairing events | once per device, ~1 per user-year | Trivial. |

**Centralized device-whitelist storage is not needed.** Each relay holds only tenants who route through it, as opaque ciphertext, plus tiny in-memory revocation set. Protocol scales horizontally because per-user state is bounded by user's device count, not network's.

## 10. Open Questions for Future ADRs

1. **Hardware mnemonic** — bind generation 0 to Coldcard-issued attestation so phishing for mnemonic is impossible without physical key theft.
2. **Quorum revocation** — k-of-n paired devices can revoke peer without mnemonic, for users who lost mnemonic but still have ≥k devices.
3. **Browser non-extractable keys via WebAuthn** — pin browser's per-device key to platform authenticator, removing "browser localStorage leaks key" failure mode.
4. **Per-request signature batching** — for high-throughput callers (calendar sync, file upload), one biscuit-bound signature authorizes batch envelope. Defer.
5. **OP_RETURN-anchored generation bump** — required vs recommended; cost on mainnet at 50 sat/vB ≈ 1500 sats per recovery; acceptable.
