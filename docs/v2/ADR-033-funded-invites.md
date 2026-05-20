# ADR-033: Funded Invites with Invitee-Claimed UTXO

**Status:** Proposed  
**Date:** 2026-05-14  
**Scope:** Tier-2 onboarding funded invites, Bitcoin spend semantics, claim/refund/rescind rules

## Context

BitSov onboarding currently models inviter-funded channel opens. This ADR studies an
alternative sovereignty model: the inviter pre-funds a small on-chain UTXO, the
invitee claims that UTXO, then the invitee opens their own Lightning channel.

Critical correction: BitSov invite identity fields are Ed25519 (`inviter_pubkey`,
`invitee_pubkey`) and are not valid Bitcoin spending keys. Bitcoin spending in
Taproot/P2WSH must use secp256k1-compatible keys or another Bitcoin-valid script.

## Decision

Use a dual-key invite contract:

1. Identity/authentication remains Ed25519 via the existing invite token flow
   (ADR-029).
2. Spend authorization uses a dedicated secp256k1 invite spend key derived from
   the existing Bitcoin key surface (separate from Ed25519 identity).
3. Funding output is a script with:
   - Immediate claim path for invitee with secp256k1 signature.
   - Time-locked refund path to inviter after expiry using
     `CHECKLOCKTIMEVERIFY`.

This gives inviter-funded onboarding without custody handoff and without abusing
Ed25519 keys as Bitcoin keys.

## Script Model

BitSov defines these keys per invite:

- `K_invitee_spend`: invitee secp256k1 pubkey (derived from invitee seed in the
  Bitcoin key namespace, not from Ed25519 identity bytes).
- `K_inviter_refund`: inviter secp256k1 pubkey for refund/rescind authority.

Reference redeem script (P2WSH form):

```text
OP_IF
  <K_invitee_spend> OP_CHECKSIG
OP_ELSE
  <expiry_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
  <K_inviter_refund> OP_CHECKSIG
OP_ENDIF
```

Semantics:

- `IF` branch: invitee can claim any time before refund spend confirms.
- `ELSE` branch: inviter can refund only at/after `expiry_height`.

Equivalent Taproot policy is acceptable if it preserves the same two spending
conditions and auditability.

## Invite Lifecycle

### 1. Issue + Fund

1. Inviter creates invite token (Ed25519-authenticated identity binding).
2. Invite metadata includes:
   - `invite_id`
   - `funding_outpoint` (set after broadcast)
   - `funding_value_sats`
   - `expiry_height`
   - `invitee_spend_pubkey_secp256k1`
   - `inviter_refund_pubkey_secp256k1`
3. Inviter broadcasts funding tx creating one dedicated output to the script.
4. Invite is shareable only after funding tx is seen (mempool) and reported to
   invitee with outpoint and amount.

### 2. Claim (Invitee)

1. Invitee validates token (Ed25519) and verifies script parameters match the
   published invite metadata.
2. Invitee builds claim tx spending the funding output to their wallet and/or
   directly into channel-open funding flow.
3. Invitee signs with `K_invitee_spend` secp256k1 key.
4. On first confirmed claim spend, invite state becomes `Claimed` and is
   terminal.

### 3. Channel Open (Invitee-Owned)

After claim confirmation policy is satisfied, invitee opens channel(s) from
claimed funds under normal BitSov/LDK rules. Channel ownership and lifecycle are
fully invitee-controlled.

## Rescind / Withdrawal

Before claim confirmation, inviter can rescind by replacing or spending the
funding output back to self (or equivalent withdrawal transaction), subject to
network policy and conflict rules.

Rules:

1. Rescind is valid only while invite state is `Funded` and unclaimed.
2. If both claim and rescind are broadcast, first confirmed spend wins.
3. Loser transaction is treated as conflicted/failed; invite transitions to the
   winner-derived terminal state.

This is explicit first-confirmed-wins concurrency semantics.

## Expiry and Refund

If invitee does not claim by expiry, inviter uses CLTV refund path:

- Refund tx spends with `nLockTime >= expiry_height` and script branch using
  `OP_CHECKLOCKTIMEVERIFY`.
- Nodes must reject pre-expiry refund attempts locally (fail-closed policy).
- After confirmed refund, invite state becomes `ExpiredRefunded` (terminal).

## Double-Claim and Concurrency Semantics

1. A funded invite corresponds to exactly one funding outpoint.
2. Because UTXOs are single-spend, two claim attempts race; only one can
   confirm.
3. State machine:
   - `Issued` -> `Funded` -> (`Claimed` | `Rescinded` | `ExpiredRefunded`)
4. Any post-terminal spend attempt is invalid and must be rejected by local
   invite state checks.
5. Reorg handling: states derived from confirmation must roll back and replay
   until finality threshold is re-met.

## Amount and Fee Policy

Define minimum funded amount conservatively so invitee can both claim and open a
channel.

Let:

- `C` = target initial channel capacity sats (policy floor).
- `F_claim` = estimated claim tx fee at configured feerate percentile.
- `F_open` = estimated channel-open funding tx fee contribution.
- `R` = reserve buffer (anchor/channel reserve + feerate volatility margin).

Required invite funding:

```text
funding_value_sats >= C + F_claim + F_open + R
```

Policy requirements:

1. Reject invite issuance if inviter funds below computed minimum.
2. Compute `F_claim`, `F_open`, and `R` from current feerate policy with a
   safety multiplier.
3. Display net spendable estimate to invitee before claim broadcast.
4. If post-claim balance cannot satisfy channel minimums, invitee may still
   receive funds normally; channel open is deferred.

Recommended initial defaults (subject to operator tuning):

- `C = 50_000 sats`
- `R >= max(5_000 sats, 10% of C)`
- Fee estimates from high-priority target (not minimum relay only).

## Key-Semantics Guardrails

1. Do not use Ed25519 invite identity keys as Bitcoin script keys.
2. All Bitcoin spend/refund keys in this ADR are secp256k1.
3. Implement explicit type separation in code and storage so identity key bytes
   cannot be accidentally routed into Bitcoin signer paths.

## Security Notes

1. Funding outpoint and script parameters must be covered by authenticated invite
   metadata to prevent substitution attacks.
2. Invite claim UI must show expiry height and current chain height.
3. Local validation must fail closed on missing/ambiguous chain state.
4. Mempool acceptance is not final settlement; terminal states require
   confirmation policy.

## Consequences

Pros:

- Better sovereignty posture: invitee opens channels from funds they control.
- Removes inviter obligation to keep liquidity channel policy for each invite.
- Uses Bitcoin-native script guarantees for expiry and refund.

Tradeoffs:

- More on-chain footprint than direct inviter channel open.
- Adds fee estimation complexity and race handling.
- Requires clear UX around expiry windows and claim timing.

## Out of Scope

1. Exact derivation path constants for invite spend keys (to be fixed in
   implementation ADR/spec).
2. Full PSBT flow details and hardware signer UX.
3. Coin selection policy beyond funded-invite output lifecycle.
