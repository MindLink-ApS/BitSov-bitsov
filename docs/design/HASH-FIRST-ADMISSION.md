# Hash-first admission: contract draft (issue #480)

Status: **draft contract, not implemented.** This document fixes the encoding, ledger states and test plan before any code changes. Nothing here changes the wire, the gate or a release. The owner decisions listed in §7 come before implementation.

## 1. Goal and the claim we may make

Issue #480 motivates checking payment before reading a paid-message body. This contract's stronger claim is limited to paid-envelope admissions on connections in the negotiated new mode: **no paid-message body application read before the payment check**. Unpaid controls still consume their declared, bounded read, parse and service budgets; the contract does not promise that every unpaid action costs only a handshake and one ledger lookup.

What the code does today (`crates/konsensus-message/src/transport/messaging.rs`, the reader loop): it reads a whole Noise transport record, decrypts it, counts the bytes against the per-peer budget, and only then parses the frame and the envelope. The gate (`crates/konsensus-core/src/gate.rs`) runs after that. Moving the payment hash to the front of today's envelope would save the envelope parse, but it would not save reading and decrypting the record.

So the contract has two levels, and each claim is made only for the level that is actually built:

| Level | What an unpaid paid-message attempt costs the receiver | Claim allowed |
|---|---|---|
| A: hash at the front of the current record | read + decrypt of one record; no envelope parse | "no envelope parsing before the payment check" |
| B: separate admission record (this contract) | read + decrypt of one fixed-size first record; one ledger lookup and reservation | "no paid-message body application read before the payment check" for paid-envelope admissions in the new mode |

Level B is the target. Level A is only an interim step, and it may ship only if §3.2 of `DESIGN-REASONING.md` is updated to the weaker claim at the same time.

Legacy and rc23 connections retain today's behaviour under §7's transition decision. They do not receive the Level B claim. Bytes already buffered by the kernel or transport remain outside the application-read claim (§5).

## 2. Negotiation

- Advertise the mode using the existing `Capability::Custom("hash_first_admission_v1")` representation in Hello/HelloAck. Do not add a capability enum variant: rc23 cannot decode an unknown variant, whereas the existing `Custom(String)` form carries the new name.
- Complete authenticated Hello/HelloAck using the existing framing, then pin the mutually supported mode for the connection from that exchange. The mode is never inferred from a subsequent record's length or content.
- A connection in this mode never falls back to legacy framing or the old paid-message path. Unknown versions fail closed under §3.
- During the transition, a node may accept old-style paid messages from peers that did not advertise the capability. The stronger claim applies only to connections in the new mode, never to the node as a whole.
- Any legacy retry permitted by the transition policy requires a separate connection negotiated in legacy mode; it is not a fallback within a new-mode connection.

## 3. Rule A: common fixed-size first record

Level B uses one complete framing rule: at each start boundary, a common fixed-size, single-chunk Noise transport record has an **authenticated type byte** selecting either `admission` or exactly one kind from the closed control list in §3.5. The admission record is this common first-record envelope; a control is not a legacy frame read to discover its type. Exact byte assignments, domain bytes, wrapper interpretation and caps are fixed and published in the implementation PR using benchmark results, before the mode is implemented. This draft selects no byte values or numeric caps.

| Field | Size | Notes |
|---|---|---|
| version | 1 byte | version for this mode; authenticated |
| record type | 1 byte | authenticated selector: `admission` or one listed control kind |
| payment hash | 32 bytes | for admission, SHA-256 preimage hash of the settled payment; canonical zero bytes for controls |
| body length / control payload length | 4 bytes, big-endian | total declared plaintext bytes in the following payload group |
| body record count / control record count | 2 bytes, big-endian | declared number of following payload records |
| domain tag | fixed | separates first records from payload frames; preserves the admission domain's purpose; exact constant set in the implementation PR |

### 3.1. Start boundary

After authenticated Hello/HelloAck, each receiving direction expects exactly one fixed-size first record whenever no declared payload group is in progress. Each direction maintains its own state.

- The fixed wrapper requires one chunk and exact encoded lengths, including the AEAD tag. A wrong first-record length is refused before decryption; no allocation scales with an advertised wrong length.
- An unknown version or type, a wrong domain, or a noncanonical unused slot is refused after one bounded authenticated decryption. A known type is acted on only after authentication.
- Refusal closes the connection without draining. No general frame reader or content-based detection is used to select the first-record decoder, and there is no fallback inside this mode.

### 3.2. Admission

The `admission` type keeps the payment hash, body length, body record count and domain semantics. Check the length and count against node limits, then check eligibility and perform §4's payer-bound atomic reservation **before any body record is read**. Limits come from benchmarks and the existing per-peer and aggregate budgets, not from new defaults.

On refusal, close with zero further application body reads as required by §5. Body records are bound to the admission by sequence. A mismatch between the admission and the decoded envelope (hash, recipient, length) refuses the message without dispatch. The envelope/gate checks and atomic acceptance requirements in §4 remain unchanged.

### 3.3. Controls and published bounds

The authenticated type byte enumerates individual allowed control kinds, including invoice requests and quote requests. The length and count slots declare that control kind's following plaintext payload and record count. Any slot a kind does not use must contain canonical zero bytes, including the payment-hash slot for all controls.

For **each** retained control kind in §3.5, the implementation PR must publish a separate bounds entry covering maximum total plaintext, maximum record count, maximum per-record ciphertext, maximum read time and a finite request/service budget. Set the exact caps from benchmarks and obtain the §7 decision before implementing the kind. Do not substitute the general frame reader's limit for any of these kind-specific bounds. Existing field caps, eligibility checks and service policy still apply.

Authenticate the first record, validate its canonical slots and declared length/count, and check that kind's eligibility and request budget **before reading its payload**. Refuse an over-cap declaration before any payload read and close without draining. Enforce the kind's per-record ciphertext and read-time limits throughout its declared group.

### 3.4. Contiguous payload groups

A first record and its declared payload group are contiguous within one sending direction. Hold writer serialization across the entire group, including the first record, so concurrent sends cannot interleave admissions, controls or their payload records.

The receiver reads only the declared records under their applicable bounds, checks that their total plaintext length equals the declaration, then returns to the start boundary. There is no interleaving and no speculative next-record read while an admission decision is pending. Full-duplex directions keep independent state; an idle direction never borrows the other direction's admission.

### 3.5. Decoder separation and frame coverage

The control path uses kind-specific schemas and **never calls the paid-envelope decoder**. It must not decode the unrestricted `Frame` enum and then reject `Message`. Existing control payload formats may be retained only behind their selected kind-specific schema and bounds, without an unrestricted frame decoder.

The table covers every current `Frame` variant in `crates/konsensus-message/src/wire.rs`. It defines the proposed closed list for the owner decision in §7; each `control:` name is a distinct symbolic type, not a byte assignment. The approved list must be fixed and published before implementation. No unlisted kind is allowed.

| Current frame kind | Treatment after entering the new mode |
|---|---|
| `Hello` | not carried in this mode; completed with existing framing before mode entry |
| `HelloAck` | not carried in this mode; completed with existing framing before mode entry |
| `Message` | `admission`, followed only after reservation by its paid-envelope body |
| `MessageAck` | control: `message_ack` |
| `MessageReject` | control: `message_reject` |
| `Ping` | control: `ping` |
| `Pong` | control: `pong` |
| `Disconnect` | control: `disconnect` |
| `PrekeyOffer` | control: `prekey_offer` |
| `SessionInit` | control: `session_init` |
| `SessionAck` | control: `session_ack` |
| `RatchetInit` | control: `ratchet_init` |
| `RequestInvoice` | control: `invoice_request` |
| `InvoiceResponse` | control: `invoice_response` |
| `InvoiceError` | control: `invoice_error` |
| `StarterRequest` | control: `starter_request` |
| `StarterStatus` | control: `starter_status` |
| `LightningInfo` | control: `lightning_info` |
| `PriceTable` | control: `price_table` |
| `PriceQuery` | control: `price_query` |
| `PriceResponse` | control: `price_response` |
| `PorchQuoteRequest` | control: `porch_quote_request` |
| `PorchQuoteResponse` | control: `porch_quote_response` |
| `PeerExchangeRequest` | not carried in this mode; legacy unpaid registry request |
| `PeerExchangeQuoteRequest` | control: `peer_exchange_quote_request` |
| `PeerExchangeQuote` | control: `peer_exchange_quote` |
| `PeerExchangePaidRequest` | not carried in this mode; contains an envelope and needs its own decision and bound |
| `PeerExchangeRefused` | control: `peer_exchange_refused` |
| `PeerExchangeResponse` | not carried in this mode; legacy registry response |
| `CallMedia` | control: `call_media`; existing live-call authorization and media budgets still apply |
| `CallOffer` | not carried in this mode; signalling uses paid envelopes via `Message` |
| `CallAnswer` | not carried in this mode; signalling uses paid envelopes via `Message` |
| `IceCandidate` | not carried in this mode; signalling uses paid envelopes via `Message` |
| `CallEnd` | not carried in this mode; signalling uses paid envelopes via `Message` |
| `Gossip` | not carried in this mode; contains an envelope and needs its own decision and bound |

This framing rule grants no new authority to session controls, acknowledgements, price exchange, discovery, gossip or media. Any additional kind that carries an envelope requires its own explicit decision and bound; it cannot enter through a control schema. Excluded frames cannot be tunneled through a listed control or trigger an in-connection fallback.

## 4. Ledger states

For a payment hash on the receiver's own ledger:

`settled-unused → reserved(conn, deadline) → consumed`, with `reserved → settled-unused` on deadline expiry or a clean refusal.

- **Eligibility, existing checks:** what the gate's settlement verification already enforces today: settlement, direction, payment hash, amounts, preimage, exclusion of channel-funding payments, and the recipient. **Proposed additions** (not enforced today; each needs its own implementation and tests): a purpose tag and an expiry window per payment. A cached `PriceTable` offer is never proof of payment.
- **Reservation is atomic**, done in the same step as the eligibility check, so two connections racing with the same hash admit at most one message.
- **Binding:** knowing a hash is not authority. Keying a reservation on the connection's key alone does not prove who paid. The contract therefore needs a **durable hash-to-payer binding** recorded when the payment settles (from what the payer committed to before paying). A reservation succeeds only when the authenticated static key of the Noise session matches that binding. A hash with no recorded binding is refused in hash-first mode, and the payer uses the legacy path during the transition. If B presents A's unused hash first, it is refused, and A's admission still succeeds afterwards, including across a restart.
- **Acceptance boundary:** the transition to `consumed` and the durable acceptance of the envelope happen in **one storage transaction**, after the envelope passes the existing gate checks (signature, freshness, nonce) and before any acknowledgement is sent. The recovery outcomes are:
  - crash before that transaction: the hash returns to `settled-unused` and the envelope was never accepted;
  - crash after it: the envelope is accepted and the hash is consumed;
  - acknowledgement lost after it: the sender's retry with the same hash is refused as consumed, with a distinct `already_accepted` result that names the accepted message, so the sender can reconcile instead of paying again.
  The hash is never consumed without an accepted envelope, and an accepted envelope never leaves the hash reusable.
- Reservations are bounded per peer and node-wide, and each has a deadline. An abandoned reservation expires. It never blocks the payer's later retry with the same hash.

## 5. Refusal behaviour

- An unknown, unsettled, wrong-recipient, consumed or wrongly bound hash refuses the admission. The receiver **does not read the body**: it closes the connection. It does not drain an attacker-chosen length to re-synchronise.
- Bytes already buffered by the kernel or transport are outside this claim. The claim covers application reads after the admission record.
- An accepted admission followed by a slow or incomplete body is bounded by the reservation deadline and the existing read timeout. It then follows §4's expiry.

## 6. Test plan (all NOT RUN; to be built with the implementation)

| Case | Pass when |
|---|---|
| Unknown / unsettled / wrong recipient / consumed hash | 0 envelope deserialiser calls, 0 body record reads, connection closed |
| First record of wrong length | refused before decryption; no allocation that scales with the advertised length |
| Exact-length, single-chunk first record | exact encoded lengths and one chunk required; alternate chunking refused before payload reads |
| First record of right length, unknown control type or version | refused after one bounded authenticated decryption, before any reservation or payload read |
| Invoice and quote exchanges in the new mode | listed invoice and quote request/response/error kinds use their first records and bounded control payloads successfully |
| Control decoder separation | 0 paid-envelope decoder calls for every allowed control kind; envelope-bearing or excluded frames cannot enter through a control schema |
| Concurrent sends | each first record and declared payload group remains contiguous under writer serialization; directions keep independent state |
| Control declaration above its kind's cap or request budget | refused before any control payload read; per-record ciphertext and read-time bounds also enforced |
| Unused hash of payer A presented first by B | refused; A's later admission succeeds, also after a restart |
| Lost acknowledgement after acceptance, then retry | refused as `already_accepted`, naming the accepted message; no second acceptance |
| Advertised body length or count above limits | refused before any body read |
| Same hash on two connections at once | exactly one admission succeeds |
| Hash reserved by a different authenticated payer key | refused |
| Header/body mismatch, reordering, truncation | no dispatch, no ledger change beyond reservation expiry |
| Crash after reserve, after consume, before ack | no duplicate admission; uncertain outcomes reconcile truthfully |
| Slow sender holding a reservation | reservation expires on deadline; per-peer and node-wide reservation counts stay bounded |
| Old-mode peer and new-mode peer on the same node | old peer keeps today's behaviour; new peer gets the new guarantee; no downgrade inside a new-mode connection |
| Legacy and rc23 exchanges | existing Hello/HelloAck and legacy invoice, quote and message exchanges unchanged without mutual support; capability uses the existing `Custom` encoding |
| Mutation: remove the pre-body admission decision | counted-read test fails because a refused admission causes a body record read |
| Mutation: remove the pre-body check or the atomic reserve | at least one test above fails |

Record exact heads, build flags and benchmark environment with every result.

## 7. Decisions before implementation (owner / security review)

1. Transition length and when old-style paid messages from new-capable peers stop being accepted.
2. Retry semantics after an expired reservation (same hash allowed again: proposed yes).
3. Treatment of a paid body that fails envelope validation after admission (proposed: refuse, hash stays usable once, with a per-payer cap).
4. Whether to ship Level A first with the weaker claim, or go straight to Level B.
5. Exact finite caps for each control kind, set from benchmarks and published in the implementation PR as required by §3.3.
6. The list of frame kinds carried in the new mode, starting from §3.5's proposed coverage and preserving decoder separation.

## 8. What this does not change

Invoice and quote requests stay unpaid and separately rate-limited, with the declared bounded control costs in §3. The handshake cost and socket limits are covered by the edge limits (`docs/operations/dos-edge.md`), not by this contract. Ingress cookies (#482) complement this work and do not replace it.
