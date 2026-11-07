# M2 — Offline delivery: sender outbox; relay carriage blocked

**Status:** Design proposal. **Nothing in this document is shipped.** It is not a
spec and it is not a commitment. **S3 (sender-side `held` outbox) is the only
ready slice. Relay `E0` carriage and the "contact has mail" dial hint are
BLOCKED pending owner rulings on Q1 and Q7, with no proposed default.**
S1/S2/S4/S5 remain blocked; their relay details below are conditional design
material, not authorization to build or enable them.

**Date:** 2026-10-23
**Scope:** How a message reaches a recipient whose node is offline when the
sender sends, on signet, in the closed beta. This covers the sender's own node
outbox, an optional paid ciphertext relay, and the recipient's admission check
when it drains.
**Supersedes nothing.** [RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md) stays
"Proposed". This document proposes the narrowest path from that proposal to a
signet MVP, and it flags where the MVP deliberately departs from it.

**Doctrine this design must hold (owner's words, restated):**

- **D-1.** Payment is the connection. There is no free first message.
- **D-2.** Admission is a settled, recipient-bound Lightning payment, one per act.
- **D-3.** Keys are identity. Bitcoin anchors energy and admission, never identity.
- **D-4.** Signet first. Today that means signet test nodes in a closed beta.
- **F1.** The target creates no pre-settlement records
  ([F1-CAPPED-FIRST-CONTACT.md](../v2/F1-CAPPED-FIRST-CONTACT.md), "Stateless
  backend requirement").

---

## 0. Where things stand today (verified on `main`, 2026-10-23)

| Piece | State | Evidence |
|---|---|---|
| Durable sender outbox, ACK-bound completion | **Shipped** (rc line, signet/regtest) | [PAID-DELIVERY-SLICE-1.md](../v2/PAID-DELIVERY-SLICE-1.md) |
| Exactly-once `operation_id` for single-recipient compose | **Shipped** | [EXACTLY-ONCE-OPERATIONS.md](../v2/EXACTLY-ONCE-OPERATIONS.md), migrations 024/025/029 |
| Offline retry of **already-paid** operations (backoff 15 s → 300 s) | **Shipped** | EXACTLY-ONCE-OPERATIONS.md, "Offline paid operations" |
| Queuing an **unpaid** message for an offline recipient | **Not built.** `create_metered_payment_proof` refuses with HTTP 400 before any payment when the peer is not connected. | `crates/konsensus-api/src/handlers/messages/compose.rs:493-498` |
| Relay wire spec | **Proposed** (16 new `Frame` variants, kind-960 binding publication) | [RELAY_PROTOCOL.md](../v2/RELAY_PROTOCOL.md) |
| Relay engine: register / deposit / drain / ack / unregister as paid kind-600..604 UKMs ("Route B") | **Code exists, default-off, never enabled on any node we run.** Mounted only when `[relay].enabled = true`. | `crates/konsensus-node/src/relay/{engine,dispatch,store}.rs`, `msg_handler.rs:542-563`, `config.rs:1912-1960` |
| Durable relay store | **Code exists.** The schema is an operator `[MANUAL]` `CREATE TABLE`, not a node migration. | `relay/store.rs:345-500` |
| Recipient-side drain client (register at a relay, pull, ack) | **Not built.** | — |
| Sender-side deposit client (find the recipient's relay, deposit) | **Not built.** | — |
| Relay discovery (`RelayBindingPublication`) | **Not built.** The proposed kind 960 is already taken by `KIND_MLS_WELCOME`. | `crates/konsensus-core/src/kind.rs:111` |
| Async / held-HTLC payments to an offline payee | **Not built**, and not available in our pinned LDK Node for this use. | — |

Today, if the recipient's node is offline, compose fails with HTTP 400. That
error's text says *"Message will be queued and sent when they reconnect"*, but
nothing is queued unless the client retries the same `operation_id` later (the
row stays `prepared`). **That message text is misleading.** S3 below fixes the
behaviour; until then, the text should not promise queuing.

### Comparison with BitChat

The comparison is taken from [BITCHAT-ALIGNMENT.md](../research/BITCHAT-ALIGNMENT.md).
That relative reference depends on companion #389; the file is not present
at this branch's base. It cites BitChat WHITEPAPER v2.0 §6.

- **Sender outbox.** 100 messages per peer, kept for 24 h, resent up to 8 times.
- **Couriers.** Up to 3 couriers per envelope. Each envelope is capped at 16 KiB and 24 h, with quotas by favourite or verified tier.
- **Nostr mailbox.** A 24 h lookback.
- **No payment anywhere.** Spam control is quotas and TTLs.
- **No forward secrecy for stored mail.** It uses one-way Noise X.

BitSov cannot copy the free parts (D-1). It can match the **limits** (24 h, 16
KiB, about 100 per peer) and beat it on stored-message secrecy, because the
Double Ratchet already seals each message.

---

## 1. The constraint that shapes everything

A Lightning payment settles only when the payee's node is online to claim the
HTLC. The payer, or something holding the payer's HTLC, must be online at that
moment too. So:

> **While the recipient's node is offline, no recipient-bound payment can
> settle. Admission (D-2) can therefore only happen when the recipient comes
> back.**

S3 keeps unpaid ciphertext on the sender's node until R is reachable and the
sender can pay. Early relay carriage of `E0` is **BLOCKED on Q1 and Q7**: a
paid relay deposit does not settle the act at R. The **act** (settled payment
plus admission) can only happen when the recipient is present.

There are only two ways to settle at drain time:

| | Who is online when the recipient returns | Mechanism | MVP? |
|---|---|---|---|
| **Mode A — pay at drain** | The sender's node, at or after the drain | The sender's outbox sees the recipient is back, pays with the existing keysend or invoice path, and delivers. | **Yes.** Uses shipped payment code. |
| **Mode B — pre-committed HTLC** | A relay or LSP holding the sender's HTLC | The sender's HTLC is held (hold-invoice style) until the recipient returns. The holder pays the recipient's invoice with the same hash and settles backwards. | **No.** Post-MVP; see §9 and Q4. |

BitSov users run their own nodes, and home nodes are meant to be up most of the
time ([home-node.md](../operations/home-node.md)). Mode A therefore covers the
common case: a sleeping laptop node or a node that is down for a few hours.
Mode A does **not** cover two nodes that are never up at the same time. Only
Mode B or an always-on node covers that, and this document says so plainly.

---

## 2. Model: sender-held delivery and blocked relay extension

### Objects

- **`M`** is the message id, `blake3(ciphertext ‖ nonce)`. It is fixed when the
  message is sealed, and it never changes across retries, re-signing or carriers.
- **`E0` (carried form)** is the sealed `UkmEnvelope` for `M`. Its
  `payment_proof` is a fixed **deferred sentinel**: zero hash, zero preimage,
  `amount_msat = 0`. The recipient's gate already floors every paid kind at
  1,000 msat, so the current ordinary receive gate rejects `E0`. S5 must
  assert this for every relayable kind, including a zero advertised price;
  this is not a guarantee about future gate paths.
  It is signed by the sender, so the relay cannot forge one.
- **`E1` (admissible form)** has the same `id`, `nonce`, `ciphertext`, `kind` and
  `references` as `E0`. It carries the **real** settled payment proof and a
  refreshed timestamp and signature (`UkmEnvelope::refresh_for_resend` already
  re-signs without touching the identity fields).

### Carriers

1. **The sender's own outbox (always).** It is the source of truth. The sealed
   `E0`, the encrypted draft and the `operation_id` live there durably.
2. **A paid relay chosen by the recipient (BLOCKED on Q1 and Q7).**
   It holds a copy of `E0` (later `E1`) under the recipient's binding. It is
   best-effort: losing the relay copy never loses the message, because the
   outbox still has it.

### Ready flow (S3, Mode A)

S seals and holds `E0` locally → its own backoff reconnects to R → re-check
price, reservation and consent (§3) → pay R → deliver `E1` directly → ACK.
No unpaid envelope leaves S; no relay, STATUS poll or dial hint is used.

### Conditional relay flow (BLOCKED on Q1 and Q7; no proposed default)

Every `E0` deposit, drain and dial hint below is blocked, including when X is
on R's own box. The diagram describes the unresolved proposal only.

```
 Sender node S                     Relay X (R's binding)          Recipient node R
 ─────────────                     ─────────────────────          ────────────────
 compose(op_id, R)                                                (offline)
   seal E0 once, persist ──┐
   state = held            │
   [opt] kind-601 DEPOSIT(E0) ──►  hold E0 under M
         (S pays X storage rent)   ◄── MessageAck
                                                                   comes online
                                   ◄── kind-603 DRAIN (R pays X)
                                   ──► E0 items (opaque)
                                                                   gate: E0 has no proof
                                                                   → not admitted,
                                                                     nothing written (F1)
                                                                   → transient dial hint:
                                                                     "contact S has mail"
 S learns R is back (any of):
  • R dials S (dial hint), or
  • S's outbox backoff connects, or
  • S polls X: kind-605 STATUS(R) → last_drain_at
 held → paying: re-check price + consent caps (§3), then pay R
 paying → paid: build E1 (same M, real proof)
 deliver E1:
  • direct, if connected ───────────────────────────────────────► gate: settled,
  • else kind-601 DEPOSIT(E1) ──►  replace E0 by M                 recipient-bound,
                                   ◄── kind-603 DRAIN              single-use →
                                   ──► E1 ──────────────────────►  ADMIT (one tx:
                                                                   nonce + receipt +
                                                                   message)
                                   ◄── kind-602 ACK(M) (R pays X)  MessageAck → S
 acked
```

"Admit on drain" means that **R's ordinary receive gate**
(`whitelist_then_verify` → `PaymentGate::verify`, bound to R's own NodeId) is
the only thing that admits. The relay never admits (FINDING 2 in
`relay.rs`), and the outbox never admits.

---

## 3. Payment

### Who pays whom, and when

Only the S → R message payment is in S3. All relay acts in this table are
conditional on the blocked relay slices and do not authorize `E0` carriage.

| Act | Payer → payee | When | How it is verified | Notes |
|---|---|---|---|---|
| Register binding (kind 600) | R → X | When R first goes online with M2 enabled, and on renewal | X's gate: settled, bound to X, single-use | Already Route B. Price is the Storage category. |
| Deposit `E0` or `E1` (kind 601) | S → X | At deposit | X's gate. Under D1 Q2-fold, the 601's own payment **is** the storage rent and must be ≥ `size × ttl × rate` | Already in code (`DepositAuth::GateSettled`). |
| Drain (kind 603) | R → X | Each batch | X's gate | R pays to download. This is why §4 caps what a depositor can make R download. |
| Ack (kind 602) | R → X | After admitting | X's gate | See Q6: should deletion be free? |
| Status (kind 605, **new**) | S → X | Polled by S while it has `held` mail for R | X's gate | Answers only to depositors who hold live items under that binding. |
| **The message itself** | **S → R** | **Only once R is reachable (Mode A)** | **R's gate, at admission** | **The admission act (D-2). Unchanged code path.** |

The relay is paid **only for carriage**. A relay payment never stands in for
the message payment. The relay cannot mint, forward or discount R's admission,
and a held `E0` proves nothing about payment.

**First contact (strangers) is out of the MVP.** F1 requires the stranger's
quote to be requested over a live Noise connection to the target, with a
quote that expires in 60 s or less. M2 does not change that: the outbox may
only hold `E0` for **existing contacts**: peers with a **prior settled,
recipient-bound admission at R from S**. A Double Ratchet session, address-book entry or
known Lightning pubkey alone does not establish that history. The sender
must also have the Double Ratchet session and known Lightning pubkey needed for delivery.
Without evidence of prior settled admission, S3 refuses held delivery; a
stranger still needs both nodes online (Q3).

### Replay and duplicates

| Threat | Prevented by | New work? |
|---|---|---|
| X replays a held `E0` | The current gate rejects the deferred sentinel proof | S5 regression test (blocked slice) |
| X replays `E1` after R admitted it | R's permanent `payment_receipts` binding → `AlreadyAccepted` → duplicate `MessageAck`, with no second message, promotion or event | No (slice 1) |
| `E1` arrives both directly and via X | Same receipt path. The first one admits, the second gets a duplicate ACK. R then sends kind-602 ACK(M) so X deletes its copy. | S5: ack relay copies of already-accepted ids |
| S's kind-601 deposit response is lost and S retries | S persists the **exact** kind-601 envelope (same nonce and proof) before paying the rent, and resends it byte for byte. X's gate sees an accepted receipt and returns a duplicate ACK **without** re-dispatching to the relay engine, so there is no second hold and no second rent. | S2: prove the dispatch is skipped on a duplicate |
| S deposits `E1` while X still holds `E0` | **Replace by `M`**, only when it is the same depositor and the same `M` and the bytes differ only in proof, timestamp and signature. Quota is not charged twice. | S2 |
| Another depositor plants a fake `M` to evict S's copy | Code already binds the held key to `blake3(ciphertext‖nonce)` (`dispatch.rs`, seam-4). Replace is scoped to the same authenticated depositor. | S2 test |
| The same payment hash is reused for a different `M` | R's gate rejects "hash reused for another envelope" | No (slice 1) |

### Exactly-once with the existing operation ids

One `operation_id` (a UUIDv4 from the client, unchanged) covers the whole life
of `M`. This design adds **one** new non-terminal state and **one** new
terminal state to `outbox_operations`.

```
prepared ──seal E0──► held
                       ├─ R reachable + caps valid ─► paying ─► paid ─► sent ─► acked
                       ├─ abandon / consent or cap failure ─► abandoned
                       └─ TTL ─► expired_unpaid

Existing prepared exits and payment_unknown / released / failed_paid semantics
remain unchanged.
```

The rules:

- **`held` has no payment evidence by construction.** The sentinel proof is not
  a payment hash. Abandon (`message_operation_abandon_v1`) is therefore allowed
  from `held` with the existing unpaid-evidence check.
- **`held → paying` is the only way out to money.** It happens under the
  per-operation lock with version CAS, exactly like `prepared → paying` today.
  S3 triggers (a backoff tick, `PeerConnected` and a client POST retry)
  therefore produce **at most one** dispatch. Relay STATUS and dial-hint
  triggers are blocked on Q1 and Q7.
- **Re-quote before delayed spending.** Compose persists the consented
  recipient amount ceiling, routing-fee ceiling and all-in spending ceiling,
  and reserves that budget. Up to 72 h later, under the same operation lock
  and CAS at `held → paying`, re-read R's current authenticated price for the
  kind (including the admission floor), revalidate the grant/consent and
  reservation, and enforce the compose-time caps. Pay only if the current
  price is within the consented recipient amount ceiling and the price plus
  the enforced maximum routing fee fits **both** the still-valid reservation
  and the consented all-in ceiling. Never silently raise a cap or reservation.
  An increased price may proceed only within all these original limits.
- **Failed consent/cap check is terminal and unpaid.** A price or fee over a
  cap, insufficient reservation, or expired/revoked consent moves `held` to
  `abandoned` with a reason visible to the sender, releases the reservation
  through the accounting queue and makes **zero payment calls**. Sending again
  requires fresh explicit consent and a new operation; a retry of the old id
  cannot revive it. If a fresh authenticated price cannot be obtained, stay
  `held` without payment and retry within the original deadline; never use the
  stale compose price.
- **The ratchet advances once, at seal.** `E0` is persisted with its ciphertext.
  Retries, re-deposits and `E1` reuse it. Re-sealing is forbidden, because it
  would burn a ratchet step and change `M`.
- **Each relay deposit (blocked on Q1 and Q7) is a child record** keyed
  `(operation_id, relay_id, form ∈ {E0, E1})`. The exact kind-601 envelope is persisted before its rent
  is dispatched, which mirrors the admission journal. A deposit with an unknown
  outcome is resent byte for byte and never re-paid.
- **`expired_unpaid` is terminal and unpaid.** It releases the budget
  reservation through the existing accounting queue. The tombstone is permanent,
  like `abandoned`.
- **A POST of the same `operation_id` in `held`** returns the `held` view with
  `retry_allowed: false`. It never pays.

---

## 4. Retention limits and size caps (MVP values)

These are proposals for signet. The relay's current `RelayPolicy::inert_default()`
is looser, and S1 tightens it.

| Limit | MVP value | Today in code | BitChat (WP §6) | Why |
|---|---|---|---|---|
| Relay hold TTL ceiling | **24 h** | 7 d (`inert_default`) | 24 h | Matches THREAT_MODEL §5 ("24-hour retention ceiling") and limits the subpoena window. |
| Sender `held` lifetime | **72 h**, then `expired_unpaid` | n/a | 24 h, 8 resends | The sender's own disk and own risk, so it can be longer than the relay's TTL. See Q5. |
| Max ciphertext per relayed envelope | **16 KiB** | 6 MiB (`MAX_CIPHERTEXT_BYTES`) | 16 KiB | Chat plus file references only. Files themselves stay live-only. |
| Relayed kinds | `KIND_CHAT` (0), `KIND_FILE_REF` (200) | same | — | 400–499 real-time signalling is stale by drain time, so it is refused. |
| Binding quota | **1 MiB** | 16 MiB | — | 64 envelopes of 16 KiB. |
| Per-depositor sub-quota per binding | **256 KiB** (16 max-size envelopes) | 4 MiB | quota by tier | One contact cannot fill R's binding. |
| Held items per binding | **128** | none (bytes only) | — | Bounds R's drain cost in items, not just bytes. |
| `held` operations per (sender, recipient) | **100** | n/a | 100 per peer | Parity. The 101st returns `409 held_queue_full` before any debit. |
| `held` operations per sender node | **1,000** | n/a | — | Disk bound. |
| Drain batch | 64 | 64 (`max_drain_batch`) | — | Unchanged. |
| Bindings per relay | 1,024 | 1,024 | — | Unchanged on signet. |
| Relays per binding (fanout) | **1** | n/a | ≤3 couriers | See §5. Fanout multiplies graph exposure. |

Deletion is **zero-on-ack**: ack deletes the row in the same transaction.
Expiry is pruned on deposit and drain (already in code). A periodic sweep is
added so an idle binding does not keep expired ciphertext on disk (S1).

---

## 5. Privacy: what the relay learns

A relay X serving R's binding learns the following. It does **not** learn
plaintext.

| X learns | Source | Severity | MVP mitigation |
|---|---|---|---|
| R's NodeId, R's IP and **when R is online** (drain cadence) | The binding and drain connections | High | R chooses X only after Q1/Q7 are resolved. A personal relay keeps metadata with R but makes unpaid `E0` storage target-side; it is not a proposed default. Tor on the R→X leg is not shipped. |
| **Who writes to R** (depositor NodeIds = R's contacts) | Authenticated kind-601 sender | **Highest** (the social graph, THREAT_MODEL §2.2) | Contacts-only bindings keep the graph to people R already knows. Fanout is 1, so only one operator sees it. |
| Inner envelope `kind` | **The `UkmEnvelope.kind` field is plaintext**, and dispatch reads it to enforce `allowed_kinds`. | Medium | See the inconsistency in §10. Relay policy needs the kind, so it cannot be hidden from X without a policy change. |
| Sizes and timing of every message | Envelope length, deposit time | Medium | Pad `E0` ciphertext to buckets (1, 4 and 16 KiB) before sealing (S3). |
| `E1`'s payment hash and amount | `E1.payment_proof` is plaintext | Medium | It links S's Lightning payment to `M`. X could correlate with LN routing if X is also a hop. Prefer direct `E1` delivery; use X only when direct delivery fails. |
| Its own storage payments from S | kind-601 settlement | Low | Inherent: S pays X. |
| Whitelist membership proofs | `WhitelistAuth` Merkle path | Medium | The MVP does not use the whitelist-sponsored path. R does not sponsor storage. Contacts-only is enforced from R's published contact root (see S1 and Q2). |

**What X never learns:** message plaintext, R's or S's keys, or ratchet state.
Stored mail is forward-secret because the Double Ratchet is unchanged. That is
stronger than BitChat's courier mail.

**What S's STATUS poll leaks:** to X, that S is waiting for R. To S, when R was
last online. That is the same as S's direct backoff dial already reveals to S.
It is not offered to non-depositors.

**What R leaks by draining:** R pays X with Lightning. If X is R's only
Lightning hop, X can link drains to R's payment activity (THREAT_MODEL §2.10).
That is a deployment constraint, not new.

---

## 6. F1 constraints on the recipient (relay extension BLOCKED)

S3 retains unpaid ciphertext only at S. The following drain rules are
conditional requirements for S5, **blocked on Q1 and Q7**, not a claim that
the relay extension conforms to F1. R's node, if drain is authorized:

1. It receives up to 64 opaque envelopes **in memory**.
2. For each one, it runs the normal gate. An `E0` fails on the zero-amount
   floor. An `E1` passes only if it is settled, bound to R and single-use.
3. **For an `E0`, it writes nothing**: no nonce, receipt, message, audit row or
   peer record. Nonces and receipts are committed only inside the acceptance
   transaction (slice 1), so the existing code already satisfies this. S5 adds a
   regression test that proves it with a storage row count before and after.
4. The **"contact S has mail" dial hint is BLOCKED on Q1 and Q7**, with no
   proposed default. Even a volatile hint from a prior admitted contact is an
   unpaid trigger for action at R. Until the owner resolves this, `E0` must
   not trigger a dial, app UI event, notification or other recipient action;
   no hint table is built or enabled. Non-contact `E0`s are also dropped.
5. It does **not** ack an `E0` at X. The item stays until S replaces it with
   `E1` or the TTL expires. R may ack, which deletes, junk it chooses to discard
   (Q6).

A relay on **R's own box is target-side infrastructure**: its `E0` rows are a
pre-settlement inbound queue, which F1 forbids. Running the same store in a
separate relay process does not remove that conflict. Third-party carriage
also makes R pay to drain acts unpaid to R. Neither contacts-only filtering
nor zero writes in R's receive gate resolves these issues. Q1 and Q7 must be
settled before any relay `E0` carriage or dial hint can proceed.

---

## 7. Failure modes

| Failure | Effect | Handling |
|---|---|---|
| X loses or never stores `E0` | No relay copy | The outbox is the source of truth. S still delivers directly when R is reachable. No money is lost, because the message is not paid yet. |
| X drops `E1` after S paid | R was paid, but the message is not received | S's op is `paid` or `sent`. The existing resend loop delivers directly when connected, or re-deposits. The money is safe (it went to R), and only delivery is delayed. |
| X lies "R is online" (STATUS) | S tries to pay | **Relay slice — BLOCKED on Q1 and Q7; not in S3.** Keysend or invoice to an offline R fails before settlement → `released`, and the op goes back to `held` with backoff. An ambiguous result → `payment_unknown` (never re-paid). X cannot redirect funds, because the payment is bound to R's Lightning pubkey. |
| X withholds `E1` forever | R never sees it | The S→R direct path is independent. X earns nothing from withholding, because rent is already paid. R can unregister (kind 604) and move to another relay. |
| R comes back briefly, then leaves again | S may pay while R is up and then fail to deliver | Payment settled → `paid`. `E1` is delivered on the next drain or connection. That is the existing paid-but-undelivered path. |
| S's node is down when R comes back | No payment, so no delivery | Mode A limit. When S comes back, its outbox retries. If the two are never up together, only Mode B helps. |
| Both nodes up but unable to dial each other (NAT, no tailnet) | No direct session | **Relay slice — BLOCKED on Q1 and Q7; not in S3.** S keysends using R's known LN pubkey (Lightning connectivity is independent), then deposits `E1` at X. R admits on its next drain. |
| Price, fee or consent drifts before `held → paying` | Delayed spending may exceed compose consent | Re-quote and revalidate under the operation lock (§3). Cap/reservation/consent failure → terminal unpaid `abandoned`, release reservation, zero payment calls. Unavailable fresh price → remain `held` until retry or expiry. |
| `held` TTL passes | The message is never paid | `expired_unpaid`, the reservation is released, and the client sees a terminal state. The relay copy expires on its own TTL. |
| Ratchet skip | R receives `M_k+5` before `M_k` | The Double Ratchet stores skipped keys up to `MAX_SKIP = 1000`. The 100-per-peer `held` cap keeps us well under it. |
| R's clock or S's clock skews | Freshness checks on `E1` | `E1` is re-signed at payment time, so its timestamp is fresh. `E0` freshness never matters because it is never admitted. |
| X restarts with the in-memory store | Held mail is lost | Already refused on a non-Mock backend (`config.rs:1941`). |

---

## 8. Threat model (deltas over THREAT_MODEL_TIER2_RELAY.md)

| Adversary | Goal | Outcome under this design |
|---|---|---|
| Paying stranger | Free first message via a relay | Blocked. Contacts-only bindings. `E0` cannot be admitted. First contact stays live-only (F1). |
| Paying contact | Spam R's drain (R pays to download) | Bounded at 256 KiB and 16 items per depositor per binding, with a 24 h TTL. R can drop the contact from its root (Q2). |
| Malicious relay | Read mail | It cannot. Ciphertext stays sealed by the Double Ratchet. |
| Malicious relay | Forge or alter mail | It cannot. Ed25519 covers the envelope. `M` is bound to the ciphertext. |
| Malicious relay | Replay mail | It is harmless. `E0` is never admitted. `E1` gets a duplicate ACK through permanent receipts. |
| Malicious relay | Make S pay without delivery | Funds reach R anyway (recipient-bound). Delivery falls back to direct. |
| Malicious relay | Map R's social graph and online pattern | **It succeeds.** This is the main residual risk (§5). Conditional mitigations are contacts-only and fanout 1. Personal relays introduce the target-side queue conflict (Q1/Q7) and are not a default. Padding and Tor are not shipped. |
| Subpoenaed relay | Recover past mail | Ciphertext only, kept up to 24 h, zero-on-ack. Metadata is recoverable. |
| Compromised R device | Read held mail | The same as reading live mail. M2 adds nothing. |
| Compromised S node | Spend S's budget on `held` mail | Spending stays inside the existing G1 grants and per-operation reservations. `held` reserves budget and only spends at `held → paying` after revalidating price, reservation and consent caps (§3). |
| Resource exhaustion on S | Fill S's disk with `held` | 100 per peer and 1,000 per node. Only S's own paired clients can create them. |
| Resource exhaustion on X | Fill the relay | Paid rent (byte × day), binding and global caps, and the per-peer register cooldown, all already in code. |

**Not addressed** (they stay open from THREAT_MODEL §6): signed shadow-ban
receipts (§6.5), push-token opacity (§6.6, and the MVP has **no push**), and
padding of signalling.

---

## 9. Mode B sketch (post-MVP, not scheduled)

Mode B is for when S's node will be offline when R returns.

1. While online, R pre-issues a small pool of **stateless** invoices to X, as in
   F1: LDK `create_inbound_payment`, no pending record, hash and amount bound
   in signed metadata, at the message price. X hands one out per deposit.
2. S pays X a **held** HTLC with the same payment hash. X does not claim it.
3. On drain, X pays R's invoice with its own liquidity. R claims it, which
   settles **to R** and writes R's ordinary receipt. X learns the preimage and
   claims S's HTLC.
4. `E1` carries a proof of that hash. R's gate verifies it as usual.

This is atomic: if R never returns, S's HTLC times out and S is refunded. It
stays recipient-bound, because only R knows the preimage.

**Costs:**

- HTLCs held for up to 24 h. This is channel jamming, needs a CLTV budget of
  roughly 144+ signet blocks plus margin, and creates force-close risk.
- Liquidity at X.
- Vouchers that live for 24 h instead of F1's 60 s.
- A relay that is now a payment hop, which makes the LN-routing leak (§2.10)
  worse.
- Our pinned LDK Node would need manual-claim support exposed for this flow.

These are listed as Q4. Nothing in S1–S5 depends on Mode B.

---

## 10. Inconsistencies found while writing this (not fixed here)

1. **Is `kind` hidden from the relay?** THREAT_MODEL_TIER2_RELAY.md §2 and §3 say
   the kind is encrypted with the payload. In fact `UkmEnvelope.kind` is a
   plaintext field (`konsensus-core/src/envelope.rs:99`), and relay dispatch reads
   the inner kind to enforce `allowed_kinds`. Either the threat model or the
   envelope has to change. The MVP assumes the kind is visible.
2. **Kind 960 is taken.** RELAY_PROTOCOL.md §5 assigns kind 960 to
   `RelayBindingPublication`, but 960 is `KIND_MLS_WELCOME`.
3. **The spec and the code describe different wire designs.** RELAY_PROTOCOL.md
   specifies new `Frame` variants with a `RelayChallenge`/`RelayAuth` handshake.
   The code implements "Route B": paid kind-600..604 UKMs through the existing
   gate, with no new frames. The MVP follows the code. RELAY_PROTOCOL.md should be
   amended or marked as superseded for the frame layer.
4. **References to missing documents.** `relay.rs` refers to
   `docs/v2/RELAY_ENGINE_BUILD_PLAN.md`, and RELAY_PROTOCOL.md refers to
   `docs/v2/OPERATOR_SOVEREIGNTY_CHARTER.md`. Neither file is in the repo.
5. **A stale comment.** The `dispatch.rs` module comment says UNREGISTER (604) is
   "STAGED, rejected", but the match arm handles it.
6. **A misleading compose error** (see §0): "Message will be queued" when nothing is.
7. **A TTL mismatch.** `RelayPolicy::inert_default().max_ttl_secs` is 7 days, but
   THREAT_MODEL §5 recommends a 24 h ceiling.

---

## 11. Milestone slices

**Only S3 is ready to build. S1/S2/S4/S5 are BLOCKED pending owner rulings
on Q1 and Q7 (and resolution of Q2 for contacts-only enforcement). No relay
`E0` carriage or dial hint has a proposed default.** The relay tests and
acceptance criteria below are conditional, not permission to implement them.

Each slice is one small PR, signet only, behind configuration that is off by
default. Every slice must pass `cargo test --workspace --locked` and
`cargo clippy --workspace --locked -- -D warnings`.

### S1 — Relay policy for M2 (relay side, config only) — BLOCKED on Q1 and Q7

- **Files:**
  - `crates/konsensus-node/src/relay.rs` (`RelayPolicy`: add `max_envelope_bytes` and `max_items_per_binding`; tighten the M2 profile)
  - `relay/store.rs` (item-count cap, periodic expiry sweep)
  - `config.rs` (`[relay]` policy keys, validation, signet-only guard)
  - Fix the stale comment from §10.5.
- **Tests:**
  - A deposit over 16 KiB → `QuotaExceeded`/new `EnvelopeTooLarge`.
  - The 129th item → refused.
  - The sweep deletes expired rows on an idle binding (SQLite and in-memory).
  - A TTL over 24 h is refused.
  - A config with `[relay].enabled` on a mainnet network → boot error.
- **Accept when:** the relay with the M2 profile enforces every value in §4, and
  existing relay tests are unchanged.

### S2 — Relay idempotency: duplicate deposits and replace by `M` — BLOCKED on Q1 and Q7

- **Files:**
  - `relay/engine.rs`, `relay/store.rs` (`hold_envelope` → upsert scoped to `(binding, depositor, M)`)
  - `relay/dispatch.rs`
  - `msg_handler.rs` (assert the relay intercept is not reached on `AlreadyAccepted`)
- **Tests:**
  - Resending the same kind-601 bytes → duplicate `MessageAck`, one held row, one receipt.
  - Depositing `E1` over `E0` from the same depositor → one row, `E1` bytes, quota unchanged.
  - Another depositor with the same `M` → refused, the original row is untouched.
  - The replacement must keep `id`, `nonce`, `ciphertext`, `kind` and `references` byte-identical, or it is refused.
- **Accept when:** a lost deposit ACK can never cost S a second rent payment or
  a second hold.

### S3 — Sender outbox: the `held` state (no relay yet)

**READY, independently of the relay slices.** This slice alone closes most of
the M2 gap for two nodes that can dial each other. It is signet-only: on
mainnet, do not advertise `message_held_delivery_v1` and refuse
`deliver_when_reachable: true` before creating a held operation, reserving
budget or making any payment call. Recovery must also refuse delayed spending
on mainnet, including a held row carried over from another network.

- **Files:**
  - `crates/konsensus-storage/migrations/{,postgres/}033_outbox_held.sql` (state constraint: `held`, `expired_unpaid`; a `held_until` column; an index)
  - `konsensus-storage/src/{sqlite,postgres}.rs`
  - `konsensus-api/src/handlers/messages/compose.rs` (opt-in request field `deliver_when_reachable: true`; capability `message_held_delivery_v1`; padding buckets; fix the §0 error text)
  - Persist compose-time recipient amount, fee and all-in consent caps with the reservation.
  - The recovery loop (`held → paying` only when connected and fresh price, reservation and consent checks pass; §3)
  - Abandon handling
- **Tests:**
  - With R offline, compose → `held`. **Zero Lightning calls** and zero relay calls, and the budget is reserved.
  - Restart keeps `held` and its deadline.
  - R reconnects → exactly **one** payment under concurrent triggers (backoff tick, `PeerConnected` and a client POST retry) → `acked`.
  - Abandon from `held` → `abandoned`, and the reservation is released.
  - Expiry → `expired_unpaid`, and the reservation is released.
  - The 101st held message for a peer → `409 held_queue_full` before debit.
  - No prior settled, recipient-bound admission at R → refused with the existing F1 message, even with a Double Ratchet session, contact entry and LN pubkey. A missing Double Ratchet session or LN pubkey also refuses held delivery.
  - After a delay of up to 72 h, a fresh price within all compose-time caps → exactly one payment at that price; increased price beyond the recipient cap or price plus routing-fee ceiling beyond the all-in cap → terminal unpaid `abandoned`, zero payment calls, reservation released.
  - Insufficient/released reservation, expired/revoked consent, or an excessive routing-fee ceiling at reconnect → the same unpaid terminal result, including concurrent retries and restart.
  - No fresh authenticated price → still `held`, zero payment calls; original TTL still expires normally.
  - Mainnet: capability absent and `deliver_when_reachable: true` refused before any held row, reservation or payment; recovery of an existing `held` row makes zero payment calls.
  - The ratchet advances once (the same `M` across restart and retry).
  - Migration upgrade from 032 keeps every existing row and checksum.
- **Accept when:** on signet, between two nodes A and B, with B stopped, a message
  sent from A is admitted by B within one backoff interval of B restarting, with
  exactly one settled payment within the revalidated caps, and all refusal
  cases above remain unpaid. The evidence goes in a `docs/testing/` file.

### S4 — Sender deposit client and relay discovery (contacts only) — BLOCKED on Q1 and Q7

- **Files:**
  - A new kind (proposed `KIND_RELAY_ENDPOINT = 904`, Control category) for R → contacts: a paid UKM `{relay_node_id, addr, binding_id}`.
  - The relay STATUS kind (`KIND_RELAY_STATUS = 605`, Storage category) in `kind.rs` and `relay/dispatch.rs`.
  - Registry check at `0095a6b4`: `crates/konsensus-core/src/kind.rs` and the taxonomy in `docs/v2/UNIFIED_PROTOCOL.md` assign neither 904 nor 605; repository search found no other kind assignment for either number. 903 is already `KIND_PEER_EXCHANGE`, and 960 is `KIND_MLS_WELCOME`. These are proposed allocations only; re-check and register them when S4 is unblocked.
  - Keep endpoint announcements outside 600–699: `msg_handler.rs:542-563` intercepts the entire Storage range when relay is enabled, so an endpoint kind in that range would be swallowed by relay dispatch.
  - A sender deposit worker in `konsensus-node` (child records `(operation_id, relay_id, form)`).
  - A storage migration `034_outbox_relay_deposits.sql`.
- **Tests:**
  - `held` with a known relay → one `E0` deposit, with the rent persisted before dispatch.
  - A lost deposit ACK → a byte-identical resend and no second rent.
  - After payment, `E1` is re-deposited (replace).
  - STATUS answers only for live depositors.
  - Without a published endpoint → outbox only (S3 behaviour).
  - The kind-904 endpoint UKM is paid and accepted only from a contact with prior settled admission; with the receiver's relay enabled, it reaches endpoint handling rather than relay-control dispatch.
  - Registry uniqueness and category tests: STATUS is 605/Storage; endpoint is 904/Control, outside 600–699.
- **Accept when:** a three-node test (A, X, B), with B offline at send time, shows
  `E0` held at X and the rent paid exactly once. B is not online in this slice.

### S5 — Recipient drain client and admit on drain — BLOCKED on Q1 and Q7

- **Files:**
  - A new `crates/konsensus-node/src/relay/drain_client.rs` (register on startup when `[m2] relay = <node_id>`, drain in batches, ack admitted and duplicate ids)
  - `msg_handler.rs` (drained envelopes keep relay provenance: replies route to the drain client, and the relay connection is never promoted; see the note below)
  - Dial-hint handling remains blocked; any implementation requires explicit owner rulings on Q1 and Q7.
  - `docs/three-node-paid-e2e.md`-style signet runbook
- **Tests:**
  - **F1 regression**: draining 64 `E0`s writes **zero** rows to any table, measured by row counts before and after.
  - The deferred sentinel proof is rejected by the gate for every relayable
    kind, including when the recipient's price is zero. This claim in §2 is
    asserted here, not assumed.
  - `E1` → admitted once. The same `E1` again (direct and relayed) → duplicate ACK, and the relay copy is acked.
  - An `E1` with someone else's proof or an unsettled proof → rejected with no record.
  - While Q1/Q7 are unresolved, `E0` creates no dial hint, connection attempt, app UI event or notification. Any owner-authorized hint design must define and test its permitted effects before implementation.
  - The relay connection is never marked `privileged` by a drained envelope.
- **Accept when** a three-node signet run (A, X, B) passes:
  1. B is stopped.
  2. A sends → `held`, and `E0` is at X.
  3. B starts and drains.
  4. A pays B once.
  5. `E1` is delivered (direct, or via X with B unable to dial A).
  6. B admits once, and A sees `acked`.
  7. X holds zero rows for B.

  The full transcript goes in a `docs/testing/` file.

> **S5 provenance note.** `transport.recv()` returns bare envelopes without the
> connection they arrived on. A drained envelope from S arrives on X's connection
> while `envelope.sender = S`. Today the gate's replies are sent to `sender`, and
> promote-on-paid looks up the connection keyed by `sender`, which is safe: the
> relay is never promoted. S5 must keep that property and test it explicitly.
> S5 must also route the relay ACK through the drain client, not the receive loop.

**What is still not done after S5:** Mode B, strangers through a relay, push or
wake, padding of signalling, fanout above 1, Tor, and the app UI in the separate
Tauri repo. None of these is claimed.

---

## 12. Open questions for the owner

Doctrine tensions are marked **⚠ DOCTRINE**.

1. **⚠ DOCTRINE — Q1, BLOCKED: may a relay hold ciphertext unpaid to R, or
   may an unpaid envelope trigger a dial at R?** Storage rent pays X, not R.
   R pays to drain `E0`s it cannot admit. If X runs on R's own always-on box,
   its `E0` rows are a target-side pre-settlement queue forbidden by F1; the
   claim that a relay is always a third party does not hold. The dial hint is
   also an unpaid actionable signal, even for a prior admitted contact.
   **No proposed default. Relay `E0` carriage and the dial hint remain BLOCKED
   until the owner resolves both Q1 and Q7.** Options for an owner ruling:
   - **(a)** Permit some `E0` carriage with caps, explicitly resolving who pays
     to drain and the target-side F1 conflict; caps alone do not resolve it.
   - **(b)** Deposit only settled `E1`s; keep all unpaid ciphertext at S.
     The relay can then help already-paid delivery when direct delivery fails.
   - **(c)** Consider headers-only drain before fetching paid items. This still
     exposes an unpaid signal and leaves any target-side `E0` store unresolved;
     it is not an approved workaround or a default.
   The ruling must separately address whether any unpaid dial trigger is allowed.
2. **⚠ DOCTRINE: contacts-only bindings.** How does X enforce "contacts only"
   without learning R's whole contact list? The current code uses a Merkle root
   of depositor NodeIds, and each depositor proves inclusion, so X learns members
   one at a time, as they deposit. Is that acceptable, or should any paying
   depositor be allowed and R simply discard on drain?
3. **⚠ DOCTRINE: strangers and M2.** Keep first contact live-only (proposed), or
   design a relay-carried F1? The latter needs Mode B or stranger vouchers, and
   both strain F1's 60-second, no-record quote.
4. **Mode B.** Is a relay holding the sender's HTLC for up to 24 h acceptable
   (jamming, liquidity, force-close risk, the relay as a payment hop)? Is it worth
   a pinned-LDK change? Or is "run an always-on home node" the answer for now?
5. **Retention.** 24 h at the relay and 72 h in the sender's outbox: are those
   the right numbers for the beta? Should `expired_unpaid` tell R anything? It
   cannot without an unpaid message, so the proposal is no.
6. **Should ack (kind 602) be free?** Charging R to delete its own mail makes
   holding the default and deletion a cost. It is small, but it is the wrong
   incentive. A free ack would need a non-gate authentication path (a signed ack
   over Noise), which Route B avoided on purpose.
7. **⚠ DOCTRINE — Q7, BLOCKED: relay placement and target-side storage.** A
   personal relay reduces third-party metadata exposure but places `E0` on R's
   own infrastructure before settlement, contrary to F1. What placement and
   paid-only storage rules are permitted, and how do they resolve Q1's drain
   cost and unpaid dial trigger? **No personal-relay or third-party default is
   proposed. Relay `E0` carriage and the dial hint remain BLOCKED on Q1 and Q7.**
8. **Spec hygiene.** Approve amending RELAY_PROTOCOL.md to "Route B" kinds,
   fixing the kind-960 clash and correcting THREAT_MODEL's "kind is encrypted"
   claim (§10). This should be a separate docs PR.
9. **Ordering.** S3 is the only ready slice and proceeds alone. S1/S2/S4/S5
   remain blocked on owner rulings on Q1 and Q7, with Q2 also required for
   contacts-only enforcement. A future ruling requires a revised relay design
   and acceptance criteria before those slices become ready.
