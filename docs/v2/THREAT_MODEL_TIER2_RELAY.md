# Tier-2 Relay — Adversarial Threat Model

> **Status:** Draft (2026-05-14; reconciled 2026-05-29). Adversarial framing. No marketing language.
> **2026-05-29 (RV-DOC-T2R0a):** the realtime-signalling *payment-gate bypass* is
> closed in code — kinds 400-499 travel as paid, gated UKM envelopes, and the legacy
> `CallOffer`/`CallAnswer`/`IceCandidate`/`CallEnd` frames are rejected (dropped with a
> warn) at both the transport reader (`messaging.rs`) and the session handler
> (`session_handler.rs`). RealTimeSignaling is priced (`static_pricing.rs`), and gossip
> is disabled (`GOSSIP_ALLOWED_KINDS = &[]`). **T2R0a is done-in-code.** The
> *call-presence metadata* a future relay would still see (who/when/SDP-shape) is a
> separate, open metadata-minimisation concern (padding/TURN), retained below.
> **Subject:** Operator-run relay peer that does store-and-forward,
> push-notification bridging, and Lightning routing for user nodes without
> ever holding user keys or decrypting payloads.
> **Scope:** Transport-1 (Noise/TCP UKM channel) and LN routing.
> Transport-2 media is out of band — relays only forward signalling UKMs,
> not the media stream.

## 1. Adversary inventory

| Adversary | Can | Cannot |
|---|---|---|
| **Subpoenaed operator** | Surrender disk state: peer pubkeys, IPs, connect/disconnect times, queued ciphertext, payment hashes, LN scid+balance. Comply with future wiretap. | Decrypt ciphertext. Forge signatures. Drain channels. |
| **Malicious operator** | Drop/delay specific recipients. Time-correlate sender↔recipient. Swap itself into the user's whitelist via UX. Sell metadata. | Forge UKMs. Issue payment proofs for users. Decrypt content. Pose as another node without key compromise. |
| **Compromised operator** | Everything above, plus modify the relay binary to ex­filtrate metadata or future ciphertext. | Break E2EE on stored ciphertext (forward-secret ratchet). Decrypt past media (DTLS-SRTP keys live on endpoints). |
| **Nation-state observer** | Correlate user IP ↔ relay IP ↔ recipient IP. Time-correlate ratchet sizes against recipient wake-ups. Map LN topology from public gossip. Compel any endpoint legally. | Passively decrypt Noise. Forge UKMs without key material. |
| **Hostile peer** | Open a whitelisted channel, pay, send crafted UKMs (parser/ratchet/rate-limiter stress). Probe presence via realtime-signal kinds 400-499 — now paid, gated UKMs (legacy `Call*` frames rejected), so no unpaid lane; the residual is the call-presence/timing metadata any relay still sees. | Anything the operator can do — has no relay role. |

## 2. Leak surfaces — what the relay actually sees

E2EE protects payload + kind (kind is encrypted alongside payload per UNIFIED_PROTOCOL §11). Everything else is visible by necessity:

1. **Sender pubkey** on every queued frame — proves identity, links sessions across reconnects.
2. **Recipient pubkey or RoomId** — *the social graph*. Highest-value leak.
3. **Frame timestamp** — supports timing correlation with off-path captures.
4. **Payment-proof hash + msat amount** — reveals message-class (chat ≈ 1 msat vs file ≈ 100+ msat) and chains custody to the user's LN node.
5. **Ciphertext length** — discriminates kind family (64-byte ≈ typing indicator, 4 MB ≈ file). Sizing alone separates chat / call-invite / file / CRDT.
6. **Signalling kinds 400-499** travel as paid, gated UKM envelopes (T2R0a — done in code); the legacy dedicated `Frame` variants (`CallOffer`, `CallAnswer`, `IceCandidate`, `CallEnd`) are decode-compatible but rejected (dropped with a warn) by launch-facing nodes, so there is no unpaid signalling lane. A relay still sees who is calling whom, when, and SDP/ICE shape unless TURN and padding are used — a metadata leak, not a gate bypass.
7. **TCP source IP** — geolocates the user unless they run Tor.
8. **Connect/disconnect cadence** — derives sleep schedule, work hours, travel.
9. **Whitelist membership** — relay knows the user's federation set.
10. **LN channel topology + routing pattern** — public gossip exposes scid + capacity; the relay also sees who the user routes to, in what amount, how often.
11. **Push-notification token (FCM/APNS)** if bridging — FCM/APNS sees the device-token ↔ relay binding and any non-opaque payload. **Biggest single leak in the design.**
12. **Retention drift** — queued ciphertext sits on disk until acked; subpoena window is days of un-collected mail per user.

Items 2, 6, 11 are the loudest.

## 3. What Tier-2 Relay DOES protect

- **Content confidentiality.** PQXDH + double-ratchet. Forward-secret and post-compromise-secure; operator never sees plaintext.
- **Kind opacity.** Kind is encrypted with payload. Relay sees "user sent ~340 bytes," not "user sent a calendar invite." Signal exposes typing/receipts as distinct transports; iMessage routes through a typed switchboard; we do not.
- **Identity sovereignty.** BIP-32 identity does not live on the relay. Rotating relays is a config change, not re-registration. Signal binds identity to a phone number.
- **Multi-relay portability.** A user can shard across N relays. Signal/iMessage cannot.
- **No central-server outage.** Relay loss degrades latency, never destroys identity or history (recipient holds the authoritative copy).
- **Operator cannot moderate content** — they don't see it. Matrix homeservers can.

## 4. What Tier-2 Relay does NOT protect

- **Social graph** (§2.2). At 1M nodes, an operator running 1% of relays sees ~10K graphs unaided — enough for cohort analysis and government-of-interest enumeration.
- **Call presence and call partners** via signalling-UKM metadata (§2.6) — the kinds are paid and gated, but the sender/recipient/timing a relay observes still answers "did A call B between t1 and t2." Answerable by *any* relay either party used.
- **Push side channel** (§2.11). FCM/APNS sees a near-realtime delivery beacon per message. Re-introduces a custodian Signal also has.
- **LN routing leak** (§2.10). When the relay is also the user's only LN hop, payment hash → recipient pubkey by watching channel updates.
- **Sleep/work pattern** (§2.8). Survives all crypto changes.
- **Passive traffic correlation** between user-uplink and relay-downlink. Noise protects bytes, not arrival times.
- **Disk-queue metadata** (§2.12) — subpoenable until ack.

## 5. Mitigation recommendations

| Weakness | Mitigation | At 1M nodes? |
|---|---|---|
| Social graph (§2.2) | **Multi-relay fanout, non-overlapping whitelists.** Each outbound frame routed through ≥2 independent relays; no single relay sees the full graph. ~2× bandwidth. | Yes — small vs LN payment cost. |
| Call presence (§2.6) | **Done (T2R0a, 2026-05-29):** signalling 400-499 are folded inside the payment gate (paid UKM), carried as ciphertext UKMs, and the parseable `Call*` frames are rejected. **Residual:** pad signalling to a size bucket + optional TURN to blunt the call-presence/timing metadata a relay still sees. | Yes; +30-80 ms setup. |
| Push token (§2.11) | **No FCM/APNS in core.** iOS TCP keepalive, Android FCM data-only with empty body, or a user-owned Tor wake-relay. Operator FCM must be opt-in with downgrade warning. | Yes (Android); iOS constrained but viable. |
| LN routing (§2.10) | **Forbid primary relay from being the user's only LN hop.** Require a second channel. BOLT-12 blinded paths when LDK-ready. | Partial; mesh-hub topology is the near-term answer. |
| Sleep correlation (§2.8) | **Cover traffic** — random-size heartbeats from every online node; recipient ratchet absorbs silently. | Marginal — only meaningful at >30% participation. |
| Traffic correlation | **Optional Tor on user→relay leg;** relay→relay stays clearnet. | Yes. |
| Disk retention (§2.12) | **24-hour retention ceiling**, zero-on-ack. | Yes. |
| Size fingerprinting (§2.5) | **Pre-encryption padding to 4-8 size buckets.** | Yes; ~30% bandwidth waste. |

Do **not** promise full Sphinx mixnet — latency blows up beyond ~100k nodes; per-message Tor circuits collapse the Tor network at our target scale.

## 6. Hard prohibition list (architectural, not policy)

Must be cryptographically impossible, not contractually forbidden:

1. **Decrypt UKM payload or kind.** Enforced by E2EE. *Current.*
2. **Modify UKM in flight.** Ed25519 signature covers envelope + ciphertext hash; relay verifies-then-forwards. *Current.*
3. **Issue payment proofs for a user.** Payment is against the recipient's invoice; relay routes, never signs. *Current.*
4. **Pose as the user.** Relay's `Hello` carries its own NodeId. *Current.*
5. **Silently shadow-ban.** Operator cannot suspend without producing a signed receipt the user can present elsewhere. *Currently policy (ADR-032); needs an architectural signed-receipt protocol — new requirement.*
6. **See plaintext push bodies.** Only opaque wake-tokens permitted. *Currently policy; must become architectural.*
7. **Strip or re-route signalling without detection.** Folding signalling into the encrypted gated path is **done** (paid UKM; legacy `Call*` frames rejected); the remaining delta is end-to-end signed ACKs endpoints can audit so a *relay* cannot drop/re-route signalling unnoticed. *Relay-tier delta, not a current-node gap.*

Items 5/6/7 are deltas. The Five Immutable Principles are silent on them today; tighten as part of accepting Tier-2 Relay.

## 7. Comparison to Signal / iMessage / Matrix

| Property | Tier-2 Relay | Signal | iMessage | Matrix |
|---|---|---|---|---|
| Content E2EE | PQXDH+ratchet | X3DH+ratchet | ECIES | Megolm (opt-in) |
| Kind opacity to server | **Yes** | No | No | No |
| Identity portable across servers | **Yes (BIP-32)** | No (phone-bound) | No (Apple ID) | Partial |
| Many relays per user | **Yes** | No | No | Yes |
| Push-token compelled | Avoidable if FCM disabled | Yes | Apple-owned | Yes |
| Group-call media via operator | No | Signal SFU | Apple | Homeserver SFU |
| Spam mitigation | Payment gate | Phone number | Apple ID | Captcha |
| Hostile-operator failure mode | Switch relay, keep identity | Lose history, re-verify | Locked out | Lose history on server |

**Strictly better:** identity portability, kind opacity, multi-relay fanout, payment-gated spam (incl. gated signalling), optional Tor user-leg. **Equivalent:** content E2EE. **Worse without mitigation:** LN routing leak is novel; call-presence/timing metadata is visible to a relay even though signalling is now gated (mitigable via padding/TURN); FCM parity is a known Signal weakness we should beat, not match.

## Cell test

A cell does not let neighbours read its ATP transactions, count its action potentials, or time its receptor opens, even while accepting hormones. Tier-2 Relay leaks 11 metadata classes a cell does not. The substrate analogy breaks (ECF is broadcast, TCP is point-to-point), but the prescription holds: the relay must be **mechanically incapable** of reading what it carries, and must minimise routing-visible state via padding, fanout, and gated signalling. Items 5/6/7 of §6 are the deltas required to pass the Cell Test at relay scope.

---

*Scale-tested mitigations only; global mixnet deferred. Items 5/6/7 mark divergences from `wire.rs` and ADR-032; treat as required deltas before promoting Tier-2 Relay from proposal to architecture.*
