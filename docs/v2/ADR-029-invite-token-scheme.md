# ADR-029 — Invite Token Scheme for Tier-2 Onboarding

**Status:** Proposed (2026-05-09).
**Decision-maker:** operator + factory writers.
**Authority:** BitSov onboarding requirements and the Five Principles.
**Implementation track:** ON-B onboarding chain.

## Context

Early onboarding was operator-driven across ~30 minutes per user: provision a node, run `konsensus init`, fund an address by hand from an operator hot wallet, manually whitelist both peers, and manually open a Lightning channel from the introducer. That works for a handful of trusted testers. It does not scale to 50.

For curated public alpha — anyone with an invite from a current user can join — the network needs an **invite-link** flow that an existing user can hand to a friend, and the friend can paste into a fresh BitSov node, and the rest is automatic: whitelist add (both sides), channel open from inviter, funding ceremony, first-message ceremony.

This ADR proposes the cryptographic scheme for the invite token and the contract between the four parties (inviter's node, invitee's node, the chain, the user).

## Constraints (immutable)

1. **Sovereign identity** — both inviter and invitee are full nodes with their own identity keys. The invite must NOT introduce a third party (no "BitSov, Inc. signs the invite").
2. **Payment-gated mesh** (Principle 2) — once whitelisted, communication still costs sats. The invite does NOT bypass payment gates; it only bypasses the whitelist gate.
3. **Closed mesh** (Principle 3) — explicit opt-in. Invite acceptance is the opt-in event from the invitee's side; invite generation is the opt-in event from the inviter's side. Both signatures are on-record.
4. **Zero plaintext at rest** (Principle 4) — invite tokens contain no plaintext message content (none planned). Invitee identity in the token is a pubkey, not a name.
5. **No custom crypto** — use only audited primitives (ed25519 via `ed25519-dalek`, hashing via `blake3` already in workspace).

## Amendments (2026-05-11)

Three amendments from PR #70 AI review, applied as fix commits on the same branch before merge:

1. **Uniform hex wire encoding.** All four byte arrays (`inviter_pubkey`, `invitee_pubkey`, `nonce`, `signature`) serialize as lowercase hex strings via dedicated serde adapters (`serde_hex_32`, `serde_hex_16`, `serde_hex_64`). The original spec only specified hex for `signature`; making it uniform avoids mixed-encoding ugliness in the base64-wrapped token form and improves cross-language interop.

2. **Domain separation tag in canonical bytes.** `canonical_bytes()` prefixes its payload with `b"bitsov-invite-v1\0"` (constant `BITSOV_INVITE_DOMAIN_V1`) before BLAKE3 hashing. Prevents the inviter's identity key from producing signatures that could ambiguously validate against any future signed payload format reusing the same primitives.

3. **`verify(&self, now_unix: u64)` takes time as a parameter.** Original `verify(&self)` shape internally called `SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()`, which silently fails OPEN on a broken clock (defaults to 0, so every non-expired invite trivially passes). Caller-supplied `now_unix` is testable without clock mocks and fail-closes at the caller boundary, consistent with the rest of the codebase's time handling.

## Amendment (2026-06-09) — `BitSovInvite` is canonical; legacy `InviteToken` routes deprecated (P3-2c)

The codebase carries **two** invite mechanisms with **non-interchangeable** token formats:

| | Legacy `InviteToken` | Canonical `BitSovInvite` |
|---|---|---|
| Routes | `POST /api/v1/invite` (issue), `POST /api/v1/invite/redeem` | `POST /api/v1/invites` (issue), `POST /api/v1/invites/accept` |
| Wire form | base58, `konsensus://invite/…` | base64url JSON, `bitsov://…` |
| Binding | none (symmetric peer-add) | ed25519-signed, **invitee-bound** (`invitee_pubkey`); `accept_invite` hard-rejects a wrong invitee |

**Decision:** `POST /api/v1/invites/accept` (the invitee-bound `BitSovInvite`) is the **canonical** Tier-2 onboarding path. The legacy `InviteToken` routes are **deprecated** and now emit RFC 8594 / RFC 9745 signalling — `Deprecation: true`, `Sunset: Sun, 31 Jan 2027 00:00:00 GMT`, and `Link: </api/v1/invites/accept>; rel="successor-version"` — plus a structured `tracing::warn!(deprecated = true)` per call so legacy-path usage is observable before any removal.

**This amendment is signalling only — no behaviour change.** The legacy routes remain fully functional. Aliasing or 410-ing `/invite/redeem` onto `/invites/accept` is **not** done and would be wrong: an `InviteToken` carries no `invitee_pubkey`, so it cannot satisfy `accept_invite`'s invitee check — aliasing would 400 ~100% of legacy traffic, and the frontend still ships `redeemInvite` (`PeerList.tsx`) and `generateInvite` (`ProfileView.tsx`). The `Sunset` date above is a **migration target, not a removal commitment**.

**Route removal is gated on the operator** ratifying: (a) a `BitSovInvite`-based peer-add UX that replaces the symmetric `redeemInvite` flow in `PeerList.tsx`, and (b) a confirmed near-zero legacy-route call rate (via the `deprecated = true` telemetry). Until both hold, the legacy routes stay.

## Decision

### Token shape

A serializable invite is a `BitSovInvite` Rust struct, serialized as JSON for the wire and base64 (URL-safe) for the human-shareable link form:

```rust
pub struct BitSovInvite {
    pub version: u8,                  // = 1 for this scheme version
    pub inviter_pubkey: [u8; 32],     // ed25519 pubkey of the issuing node
    pub invitee_pubkey: [u8; 32],     // ed25519 pubkey of the receiving node
    pub expiry_unix: u64,             // unix seconds; reject on accept after expiry
    pub channel_size_hint_sats: Option<u32>,  // inviter's hint for channel capacity
    pub nonce: [u8; 16],              // random; ensures uniqueness across re-issues
    pub signature: [u8; 64],          // ed25519 sig over canonical_bytes(self_minus_signature)
}
```

The `canonical_bytes()` of the unsigned struct is the BLAKE3 hash of the strictly-ordered concatenation of all fields except `signature` itself, in the field order above. The signature covers that hash.

### Generation (inviter side)

The inviter's node signs the struct with its identity key:

```text
1. Operator (or invitee, see "Operator-vs-self issuance") provides the invitee_pubkey
   to the inviter via an out-of-band channel (Signal, in-person, etc.).
2. Inviter's POST /api/v1/invites { invitee_pubkey, expiry_unix, channel_size_hint_sats }
   returns:
   - invite_id (uuid v4, stored locally for tracking)
   - invite_token_b64 (base64-url-safe encoding of canonical JSON of BitSovInvite)
   - invite_link: "bitsov://invite/<invite_token_b64>"
3. Inviter shares the invite_link or invite_token_b64 with the invitee
   (Signal, email, paper QR).
```

The invitee's pubkey is required at issuance because:
- It binds the invite to a single recipient (no replay across users)
- It lets the inviter's node pre-emptively whitelist that pubkey on issuance, so when the invitee comes online and connects, the handshake succeeds without a manual whitelist step

This means invite generation is **non-anonymous**: the invitee must surface their pubkey to the inviter before the invite is created. For curated invites this is acceptable — invite is relationship-scoped, and the pair already trusts each other. Open admission will need a different flow (see "Out of scope" below).

### Acceptance (invitee side)

```text
1. Invitee runs konsensus init on their fresh node, generating their identity.
2. Invitee pastes the invite_token_b64 (or full invite_link) into their UI.
   Frontend POSTs to invitee node's POST /api/v1/invites/accept { token }.
3. Invitee node:
   a. Decodes the base64 to BitSovInvite
   b. Verifies signature against inviter_pubkey (using ed25519-dalek)
   c. Verifies expiry_unix > now
   d. Verifies invitee_pubkey == this_node's_identity_pubkey (rejects if not)
   e. Adds inviter_pubkey to whitelist (Storage::add_whitelisted_peer)
   f. Stores invite_id locally in `accepted_invites` table (single-use enforcement)
   g. Initiates Noise_XX handshake to inviter at the address it has on record
      (from federation gossip, or operator-pre-shared)
   h. Returns 202 Accepted with { inviter_pubkey, expected_address, channel_size_hint }
4. Invitee node connects to inviter node via Noise_XX.
5. Inviter node, on receiving connection from already-whitelisted invitee, sees
   "this is one of my pending invites" and triggers auto-channel-open
   (size = channel_size_hint_sats or operator-default 50_000 sats).
6. Channel opens (6 confirmations). Both sides emit WS event "onboarding_complete".
7. Invitee UI advances to "send first message" wizard.
```

### Single-use enforcement

The invite_id is recorded in a new `accepted_invites` table on both sides:
- Inviter side: created at issuance with `state='pending'`. Updated to `state='accepted'` when the invitee's node connects with a matching pubkey.
- Invitee side: created at acceptance with the inviter_pubkey and expiry. Reject if same `nonce` is re-presented (defense against operator replaying invites).

A second attempt to accept an already-accepted invite is rejected with HTTP 409.

### Revocation

Inviter's `DELETE /api/v1/invites/:id`:
1. If the invite is `pending`, mark it `revoked` locally.
2. If the invite has been `accepted`, the channel and whitelist entry remain (the revocation is for issuance, not for the relationship). Operator removes the peer separately via `peers remove`.

A pending revoked invite, if presented to the invitee node, fails at the inviter-side handshake (the inviter's node has marked it revoked locally and won't auto-channel-open). The invitee sees a "this invite has been revoked by the inviter" error.

### Funding ceremony (companion flow)

ADR-029 doesn't strictly cover funding, but the onboarding state machine ties them together. After invite acceptance:

```text
- If invitee chose Light tier: they're funded by the inviter's auto-channel-open.
  No on-chain funding needed.
- If invitee chose Full tier: they need on-chain Bitcoin to open their own channels.
  Funding ceremony UI:
    1. Display invitee's funding address + QR
    2. Poll the chain (via the existing ChainProvider trait) every 30s
    3. When ≥1 confirmation, advance to "open your first channel" step
  The inviter's pre-opened channel still works regardless — the invitee
  has inbound liquidity from day one.
```

Funding-poll state lives in a new `onboarding_state` table, single-row,
with fields: `current_step`, `funding_address`, `funding_amount_sats_required`,
`funding_amount_sats_received`, `last_poll_at`.

## Out of scope (deferred to a future ADR)

1. **Open-admission invites** — anyone-can-join with no inviter. Requires
   bootstrap discovery (DHT or curated list), Sybil controls, and a non-curated
   funding ceremony. Probably a future ADR.
2. **Relay-tier provisioning** — pairing a user-held identity with an operator
   relay. This must not introduce operator-held mnemonics or custodial node
   control.
3. **Multi-party invites** — the same invite link works for N invitees. Useful
   for "post in a Telegram group" but breaks single-use enforcement. Out for
   v2.0.
4. **Invite expiry sweeping** — automatic GC of expired pending invites.
   Operational nicety; ship as L-track follow-up if cardinality grows.

## Operator-vs-self issuance

Two distinct operational modes, both supported by the same scheme:

### Operator-issued

Operator runs `bitsov invite create --invitee <pubkey>` on their node, gets an
invite link, sends to invitee via Signal/email. Invitee pastes into their
fresh node's UI.

### Self-issued (peer-to-peer)

A non-operator peer issues an invite to a friend. Same scheme, different
issuing node. Recipient ends up whitelisted on the issuing peer's node, not
on the operator's. Each peer maintains its own whitelist; this is a feature
of the closed-mesh principle.

For curated networks, both modes are admissible. The operator's role is just to be the
first issuer; from there invites can fan out peer-to-peer at the inviter's
discretion.

## Five Principles audit

| Principle | Compliance |
|---|---|
| 1 — Sovereign identity | ✅ Both ends are pubkeys; no third-party issuer. |
| 2 — Lightning gate | ✅ Whitelist bypass only; payment gate still applies after acceptance. |
| 3 — Closed mesh | ✅ Explicit opt-in by both sides. Invite issuance + invite acceptance both signed. |
| 4 — Data sovereignty | ✅ Invite contains no plaintext message data. |
| 5 — Timechain pricing | N/A (onboarding is not a pricing event). |

## Test plan

- [ ] Unit tests in `konsensus-core` for `BitSovInvite::sign`, `::verify`, `::is_expired` (target ONB1)
- [ ] Integration test: alpha generates invite for a fresh test-pubkey; second node accepts; whitelist added on both sides (target ONB3 + ONB4)
- [ ] Integration test: auto-channel-open on first connection from invitee (target ONB5)
- [ ] Replay test: same invite presented twice → second rejected with 409 (target ONB3)
- [ ] Expiry test: token with `expiry_unix < now` → rejected (target ONB1)
- [ ] Wrong-invitee test: token with mismatched `invitee_pubkey` → rejected (target ONB3)
- [ ] Frontend e2e: paste invite → confirmation modal → click accept → first-message wizard appears (target ONB7 + ONB9)

## Open questions

- **Minimum channel size** — operator-default 50k sats? Configurable per-invite via `channel_size_hint_sats`. Decide on a floor (e.g., 25k) below which the invite is rejected at issuance. Defaulting at 50k for now; revisit after first 5 real invitees.
- **Auto-channel-open vs explicit confirm** — should the inviter's node ask the operator before each auto-open, or open silently? Curated-alpha default: open silently with an operator notification. Operator can DELETE if undesired.
- **Address-of-inviter discovery** — the invite contains the inviter's pubkey but not their network address. The invitee needs to know how to reach the inviter. Options: (a) embed `address` field in the invite (binds it to a snapshot), (b) federation gossip from any bootstrap peer, (c) operator-curated bootstrap list. **Decision pending; default to (a) for v1 and revisit when gossip ships.**
