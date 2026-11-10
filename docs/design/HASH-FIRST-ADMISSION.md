# Hash-first admission: contract draft (issue #480)

Status: **draft contract, not implemented.** This document fixes the encoding, ledger states and test plan before any code changes. Nothing here changes the wire, the gate or a release. The owner decisions listed in §7 come before implementation.

## 1. Goal and the claim we may make

Issue #480 asks that an unpaid peer cause no work beyond the transport handshake and one ledger lookup.

What the code does today (`crates/konsensus-message/src/transport/messaging.rs`, the reader loop): it reads a whole Noise transport record, decrypts it, counts the bytes against the per-peer budget, and only then parses the frame and the envelope. The gate (`crates/konsensus-core/src/gate.rs`) runs after that. Moving the payment hash to the front of today's envelope would save the envelope parse, but it would not save reading and decrypting the record.

So the contract has two levels, and each claim is made only for the level that is actually built:

| Level | What an unpaid paid-message attempt costs the receiver | Claim allowed |
|---|---|---|
| A: hash at the front of the current record | read + decrypt of one record; no envelope parse | "no envelope parsing before the payment check" |
| B: separate admission record (this contract) | read + decrypt of one fixed-size record; one ledger lookup and reservation | "no body read before the payment check" |

Level B is the target. Level A is only an interim step, and it may ship only if §3.2 of `DESIGN-REASONING.md` is updated to the weaker claim at the same time.

## 2. Negotiation

- A new capability, `hash_first_admission_v1`, is advertised in the federation Hello like the others. It is JSON name-tagged, so existing encodings do not shift.
- The mode is fixed per connection when both sides advertise it. It is never inferred from the traffic.
- A connection in this mode never falls back to the old paid-message path. Unknown versions fail closed.
- During the transition, a node may accept old-style paid messages from peers that did not advertise the capability. The stronger claim applies only to connections in the new mode, never to the node as a whole.

## 3. Admission record (encoding to be finalised in the implementation PR)

One Noise transport record, fixed size, sent before the body records of a paid message.

| Field | Size | Notes |
|---|---|---|
| version | 1 byte | `0x01` |
| record type | 1 byte | `admission` |
| payment hash | 32 bytes | SHA-256 preimage hash of the settled payment |
| body length | 4 bytes, big-endian | total plaintext bytes of the body that follows |
| body record count | 2 bytes, big-endian | number of body records that follow |
| domain tag | fixed | separates admission records from frames; the exact constant is set in the implementation PR |

Rules:
- The receiver reads this record with a **fixed maximum length** equal to its encoded size plus the AEAD tag. A record of any other length is refused before decryption, and the connection closes.
- `body length` and `body record count` are checked against node limits before any body byte is read. Limits come from benchmarks and the existing per-peer and aggregate budgets, not from new defaults.
- Body records are bound to the admission by sequence. A mismatch between the admission and the decoded envelope (hash, recipient, length) refuses the message without dispatch.

## 4. Ledger states

For a payment hash on the receiver's own ledger:

`settled-unused → reserved(conn, deadline) → consumed`, with `reserved → settled-unused` on deadline expiry or a clean refusal.

- **Eligibility** is the existing gate's settlement rule: settled, bound to this recipient, unused, and inside its amount, purpose and expiry terms. A cached `PriceTable` offer is never proof of payment.
- **Reservation is atomic**, done in the same step as the eligibility check, so two connections racing with the same hash admit at most one message.
- **Binding:** a reservation is keyed by the payment hash **and** the payer's authenticated static key from the Noise session. Knowing a hash is not authority. A hash seen by a third party cannot be reserved by that party.
- **Consumed** is written only after the full envelope passes the existing gate checks (signature, freshness, nonce) and before dispatch is acknowledged. A crash between reservation and consumption returns the hash to `settled-unused` on restart. It never consumes the hash without a delivered message.
- Reservations are bounded per peer and node-wide, and each has a deadline. An abandoned reservation expires. It never blocks the payer's later retry with the same hash.

## 5. Refusal behaviour

- An unknown, unsettled, wrong-recipient, consumed or wrongly bound hash refuses the admission. The receiver **does not read the body**: it closes the connection. It does not drain an attacker-chosen length to re-synchronise.
- Bytes already buffered by the kernel or transport are outside this claim. The claim covers application reads after the admission record.
- An accepted admission followed by a slow or incomplete body is bounded by the reservation deadline and the existing read timeout. It then follows §4's expiry.

## 6. Test plan (all NOT RUN; to be built with the implementation)

| Case | Pass when |
|---|---|
| Unknown / unsettled / wrong recipient / consumed hash | 0 envelope deserialiser calls, 0 body record reads, connection closed |
| Admission record of wrong length or type | refused before decrypt; no allocation that scales with the advertised length |
| Advertised body length or count above limits | refused before any body read |
| Same hash on two connections at once | exactly one admission succeeds |
| Hash reserved by a different authenticated payer key | refused |
| Header/body mismatch, reordering, truncation | no dispatch, no ledger change beyond reservation expiry |
| Crash after reserve, after consume, before ack | no duplicate admission; uncertain outcomes reconcile truthfully |
| Slow sender holding a reservation | reservation expires on deadline; per-peer and node-wide reservation counts stay bounded |
| Old-mode peer and new-mode peer on the same node | old peer keeps today's behaviour; new peer gets the new guarantee; no downgrade inside a new-mode connection |
| Mutation: remove the pre-body check or the atomic reserve | at least one test above fails |

Record exact heads, build flags and benchmark environment with every result.

## 7. Decisions before implementation (owner / security review)

1. Transition length and when old-style paid messages from new-capable peers stop being accepted.
2. Retry semantics after an expired reservation (same hash allowed again: proposed yes).
3. Treatment of a paid body that fails envelope validation after admission (proposed: refuse, hash stays usable once, with a per-payer cap).
4. Whether to ship Level A first with the weaker claim, or go straight to Level B.

## 8. What this does not change

Invoice and quote requests stay unpaid and separately rate-limited. The handshake cost and socket limits are covered by the edge limits (`docs/operations/dos-edge.md`), not by this contract. Ingress cookies (#482) complement this work and do not replace it.
