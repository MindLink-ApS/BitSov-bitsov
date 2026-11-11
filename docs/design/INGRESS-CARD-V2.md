# Ingress card v2: contract draft (issue #482)

Status: **draft contract, not implemented.** This document fixes the card format, the dial rule and the test plan for advertising more than one ingress path before any code changes. Nothing here changes the wire, the edge limits, the payment gate or a release. The decisions listed in §6 come before implementation.

## 1. Goal and the claim we may make

Issue #482 asks that a node not depend on a single exposed address, and that handshake floods be cheap to refuse. Most of the second half already exists (§2). The missing piece is that a signed card can name only one endpoint, so a peer has nowhere else to go when that address is flooded or null-routed.

The claim this contract supports, once built: *a peer holding a valid card can try every path the owner signed, in the owner's order, within one bounded deadline, and every path must prove the same node key.* It does not claim anonymity, it does not claim that the listed paths fail independently, and it does not protect any single path against volumetric saturation.

## 2. What the code does today (main, identical to rc23 for every file cited)

### 2.1 Pre-Noise cookies

`crates/konsensus-message/src/transport/cookie.rs`:

- `:1-32` A stateless return-routability cookie, `HMAC(secret, src-ip ‖ epoch)`, checked before any Noise DH. No per-client record and no Noise state are created before it verifies.
- `:53`, `:56`, `:64` A self-describing `BSc1` frame of fixed 38 bytes; any frame read before the cookie verifies is capped at 64 bytes.
- `:72`, `:77` 30-second epochs (current and previous accepted); the secret rotates every 4 epochs and two generations are kept.
- `:88-102` `CookieMode` is `disabled`, `adaptive` (default) or `required`. The `difficulty` byte is reserved at 0, so there is no proof-of-work (`:26-29`).
- `:180`, `:192` `issue` and `verify` take the source `IpAddr`.

`crates/konsensus-message/src/transport/handshake.rs:28-65`: the initiator sends an optimistic Noise message 1, answers a cookie challenge if one comes back, and restarts with a fresh Noise session.

### 2.2 Edge limits

`crates/konsensus-message/src/transport/edge.rs`:

- `:3-25` `DosEdgeConfig`: connection and handshake token buckets, `max_pending`, `max_handshakes`, `max_per_ip`, `max_per_subnet`, `cookie_threshold`, `max_tracked_sources`, `cookie_timeout_secs`, `handshake_timeout_secs`.
- `:27-44` Defaults (for example `max_per_ip = 4`, `max_per_subnet = 8`, `cookie_threshold = 32` of `max_handshakes = 64`).
- `:48-71` `validate` refuses non-finite or zero rates, unbounded capacities, `max_per_ip > max_per_subnet`, `cookie_threshold` outside `(0, max_handshakes)` and a cookie timeout longer than the total handshake timeout.

`crates/konsensus-message/src/transport/connection.rs`:

- `:76-87` `subnet_key`: the full IPv4 address, or the IPv6 /64. IPv4 is not aggregated to /24; `docs/operations/dos-edge.md` records that the /24 aggregation the issue mentions was removed.
- `:89-125` Bounded token-bucket tables that never forget a source with active debt.
- `:311-337` The listener keys every budget on the accepted socket's source address (`addr.ip().to_canonical()`), then decides whether a cookie is required.

`docs/operations/dos-edge.md` describes these limits, their defaults and their residual risk. This contract changes none of them.

### 2.3 Cards carry one endpoint

`crates/konsensus-core/src/front_door.rs`:

- `:26` Signature domain `bitsov-front-door/v1\0`; `:28` `VERSION = 1`; `:36` whole card at most 16 KiB; `:37` `MAX_ENDPOINT_LEN = 255`.
- `:183-208` `FrontDoorCard` has one `endpoint: String` and one `reach`, with `deny_unknown_fields`. `:210-228` `FrontDoorFields` (the owner-supplied input) has one `endpoint: String` and **no** `reach` field; `issue_with_key` (`:236-238`) derives `reach` from that single endpoint with `reach_of_endpoint`. v2 issuance keeps this: the owner supplies entries without `reach`, and issuance derives each entry's `reach` from that entry's own `endpoint`, never from another entry or a card-level value.
- `:266-313` The signature covers canonical JSON of every field except `sig`; `:324-325` any `v` other than 1 is refused as `UnsupportedVersion`.

`crates/konsensus-core/src/introduction.rs`:

- `:48` Signature domain `bitsov-introduction/v1\0`; `:54` 10-minute lifetime; `:58` encoded form at most 2048 bytes.
- `:121-146` `Introduction` has one `endpoint` and one `reach`, with `deny_unknown_fields` and no `seq`.
- `:206` Fixed-order, length-prefixed canonical bytes; `:235-236` refuses any other version.

Dial paths: `crates/konsensus-api/src/handlers/front_door.rs:566-590` and `crates/konsensus-api/src/handlers/introduction.rs:341-366` each resolve the single `card.endpoint` once under a 5-second DNS deadline, refuse it unless every resolved address passes `dial_allowed` for the card's reach, and return the first address. `open_front_door` (`front_door.rs:592-631`) and `open_introduction` (`introduction.rs:380-411`) then dial that pinned address under a 10-second deadline, and the Noise handshake must prove the card's node key.

Card ordering: `crates/konsensus-core/src/card_cache.rs:1-45` keeps verified front-door cards in memory, keyed by `node_id`, at most 512; a higher `seq` replaces a lower one and an equal or lower `seq` is stale. The publishing side keeps a monotonic `seq` floor on disk (`handlers/front_door.rs:33-51`).

### 2.4 The storage relay is a different mechanism

`crates/konsensus-node/src/relay.rs:1-24` is ciphertext store-and-forward, default-off behind `[relay].enabled`. It holds envelopes for later drain; it does not accept Noise connections on a node's behalf and does not forward a live handshake. It is **not** an ingress path and is out of scope for this contract unless separately designed.

## 3. Card v2

Both card kinds get a v2. A v2 card replaces the single `endpoint`/`reach` pair with an `endpoints` list. Every other field keeps its v1 meaning and v1 bounds.

### 3.1 Signature domain and version

| Card | v2 domain tag | `v` |
|---|---|---|
| Front door | `bitsov-front-door/v2\0` | `2` |
| Introduction | `bitsov-introduction/v2\0` | `2` |

- A v2 signature never verifies under a v1 domain and the reverse. A verifier picks the domain from `v` and refuses a card whose `v` it does not support. It never tries a second domain after the first one fails.
- v2 types are separate structs with `deny_unknown_fields`. A v1 card cannot be read as v2 (missing `endpoints`), and a v2 card cannot be read as v1 (unknown field, and `v != 1`).
- Whether v2 links keep the existing prefixes or use new ones is decision §6.4.

### 3.2 Endpoint entry and bounds

```text
endpoints: [ { kind, endpoint, reach }, ... ]
```

| Field | Rule |
|---|---|
| `kind` | `"direct"`: a `host:port` that terminates the node's own Noise handshake, whether on the home line or forwarded by an owner-chosen host. Other values are reserved (§6.2). |
| `endpoint` | Same syntax, length limit (255 bytes) and `reach_of` check as v1, per entry. |
| `reach` | Per entry. `public` may never be a literal local address, as in v1. |

Hard caps, checked before signature verification and before any DNS lookup:

- **at most 4 entries** (`MAX_ENDPOINTS`), at least 1;
- each `endpoint` at most 255 bytes;
- the whole front-door card stays at most 16 KiB;
- the encoded introduction stays at most 2048 bytes. If four maximum-length entries do not fit, the introduction cap is lowered to fit rather than the size limit raised (decision §6.3).

Canonical form: the issuer writes each entry in canonical form (trimmed, lower-case DNS host, bracketed IPv6 literal, explicit port). A verifier refuses a non-canonical entry instead of normalising it, so two encodings of one card cannot both verify. Two entries with the same canonical `endpoint` refuse the whole card.

Entries with a reserved `kind` are covered by the signature and count against the caps, but are never dialed by a reader that does not support them. A card with no entry the reader can dial is valid to display but cannot be opened.

### 3.3 Ordering and selection

- The list order is the owner's preference order and is signed exactly as written. A reader never re-sorts before verifying or dialing.
- `open` tries entries strictly in list order, one at a time. For each entry it:
  1. skips a `local` entry unless the reader approved that specific entry (consent is per entry, not per card);
  2. resolves once under the existing DNS deadline and refuses the entry unless every resolved address passes `dial_allowed` for that entry's reach (today's `pin_endpoint`, applied per entry);
  3. dials the pinned address, and requires the Noise handshake to prove the card's `node_id`.
- **Attempt cap:** at most one dial per entry, so at most 4 per `open`. **Total deadline:** one deadline for the whole `open`, not renewed per entry (value in §6.5). Each failed or cancelled attempt releases its socket before the next starts.
- An entry whose handshake proves a different key is a failed entry. The reader moves on and never accepts the other key.
- **Unauthenticated refusals continue the walk.** Today a closed-mesh responder sends `Frame::Disconnect` *before* `HelloAck` (`crates/konsensus-message/src/transport/handshake.rs:401-415`), and the initiator turns any pre-`HelloAck` `Disconnect` into `TransportError::Rejected` (`:320-322`) without having verified the responder's identity binding or Ed25519 key. The expected-key comparison happens only afterwards (`:510-527`), and a wrong key also surfaces as `TransportError::Rejected`. Under Noise_XX the responder's static key is not pinned in advance, so a pre-`HelloAck` `Disconnect` can come from any key, including an on-path party or a different node at that address. The reader therefore treats every refusal that is not authenticated as the card's `node_id` (a pre-`HelloAck` `Disconnect`, a wrong key, a version mismatch, a cookie or edge refusal, a transport error) as a failed entry and moves to the next entry.
- **Authenticated refusals stop the walk.** Only a refusal that arrives after the reader has verified the identity binding, matched it to the Noise remote static key and matched the node key to the card's `node_id` stops the walk: that node answered, and other paths would get the same answer. Today's wire has no such refusal for a closed mesh, so v2 `open` cannot rely on it. The implementation must split the current single `Rejected` error into at least `RefusedUnauthenticated` and `RefusedByExpectedKey` (names illustrative); whether a responder should send an authenticated refusal (for example a signed refusal or `HelloAck` followed by `Disconnect`) is a wire question outside this contract and is not assumed here.
- The user-facing outcome after a full walk reports the strongest evidence seen: "refused by this node" only if some entry gave an authenticated refusal; otherwise "could not reach this node", with unauthenticated refusals counted as failures.
- No fallback outside the list: not to a previously cached endpoint, a STUN result, an older card or any address the signed card does not name.

### 3.4 Downgrade rule

The risk is not forgery: an old v1 card is genuinely signed by the node and, until it expires (at most 7 days for a front door), still verifies. Presenting it to a reader steers that reader to one endpoint, possibly the one under load. Because Noise still pins the key, the harm is availability, not impersonation.

Rule: **a v2-capable verifier never accepts a v1 card of either kind (front door or introduction) for a `node_id` while it holds an unexpired downgrade marker for that `node_id`.** Both card kinds are signed by the same node key (`introduction.rs:126-127`: an introduction's `node_id` is the introducer's own key), and a node that issues v2 issues both kinds as v2, so a v2 sighting of either kind marks the node for both.

**Downgrade marker.** `node_id → marker_expiry`, keyed only by `node_id`. It does not depend on `seq`, so a v2 introduction (which has no `seq`) sets it exactly like a v2 front-door card. It is written when:

1. a v2 front-door card verifies (whether or not the card cache stores it);
2. a v2 introduction verifies, with or without any front-door cache entry for that `node_id`;
3. optionally, the peer advertises a capability inside an authenticated session (`front_door_card_v2`). This is learned only after a connection, so it protects later opens, not the first one.

The marker check runs before the card cache sees a v1 card, so it applies to every v1 card regardless of its `seq`.

**Retention.** The marker must outlive every v1 card that could be replayed against it. A v1 front-door card lives at most `LIFETIME_SECS` (7 days, `front_door.rs:33`) from its signed `issued_at`, with `MAX_SKEW_SECS` (60 s, `:35`) tolerated; a v1 introduction lives 10 minutes. On each v2 sighting the marker is refreshed to

```text
marker_expiry = max(existing, v2.expires_at, now + LIFETIME_SECS + MAX_SKEW_SECS)
```

using the verifier's own clock for `now`. It is not tied to the v2 card's expiry: a shorter-lived v2 card (an introduction, or a front-door card nearer its end) does not shorten it. Any v1 card issued at or before the last v2 sighting therefore expires before the marker does. The guarantee is narrowed for one case: a v1 card the node itself issues *after* the reader's last v2 sighting (for example the v1 half of a later transition pair, §3.5) can be accepted once the marker has run out, which requires the reader to have seen no v2 card from that node for a full v1 lifetime.

**Persistence.** Markers are written to disk durably before the v2 card is reported as verified, and reloaded at start-up, so restart and card-cache eviction do not clear them. A marker store that cannot be read at start-up is reported to the owner; until a marker is rewritten, the guarantee for the affected nodes lapses (this is stated, not hidden).

**Bounded table and eviction.** A marker is a 32-byte key plus an 8-byte expiry, so the table bound is set well above the card cache (`MAX_DOWNGRADE_MARKERS`, proposed 65,536, under 3 MiB of raw entries; final value in §6.3). When an insert finds the table full, expired markers are pruned first. If none is expired, the marker with the earliest `marker_expiry` is evicted and the eviction is counted and logged. For the evicted `node_id` the guarantee lapses until its next v2 sighting: this is an explicit narrowing, not a silent one. A refresh of an existing marker never evicts another entry.

**Sequence numbers and cache order.** v1 and v2 front-door cards from one node share one monotonic `seq` space (the existing floor, `handlers/front_door.rs:33-51`). The card cache holds at most one card per `node_id`, of either version, and today's rule (`card_cache.rs:32-50`: an incoming card with `seq <= held.seq` is stale) still governs v1-over-v1 and v2-over-v2. Two additions make the versions compose:

- **Issuers never give a v1 and a v2 card the same `seq`.** A transition pair (§3.5) takes two consecutive values from the floor, v1 first and v2 second, so the v2 card is strictly higher. With either arrival order the v2 card ends up held: v1 then v2 is an ordinary higher-`seq` replacement; v2 then v1 leaves v1 stale and also marker-refused.
- **A verified v2 card replaces a held v1 card regardless of `seq`.** A held v1 card is never dialable once the v2 marker exists, so keeping it would leave the node unreachable. This covers equal `seq` from a non-conforming issuer and a v2 card from an older pair arriving after a newer v1 card. It never lets a v1 card displace a held v2 card.

Residual risk, stated plainly: a reader with no marker for a node (first contact, or after the marker expired, was evicted or could not be reloaded) cannot tell a stripped v1 card from a node that never upgraded. That case is limited to availability and ends at the v1 card's expiry or the reader's next v2 sighting of either kind.

### 3.5 Transition

- **Old readers** refuse v2 cards with `UnsupportedVersion` or `Malformed`. They fail closed and show no endpoint.
- **New readers** accept v1 cards from nodes without a downgrade marker, and dial the single endpoint as today.
- **Publishing nodes** issue v2 by default once built. During a transition window the node may also issue a paired v1 card, one `seq` below its v2 partner (§3.4, never the same `seq`), whose `endpoint` equals the first eligible v2 entry, so old readers still reach the owner's preferred path. Whether to issue that pair, and for how long, is decision §6.1.
- After the window the node stops issuing v1. Readers keep accepting v1 from nodes without a marker until a later release decides otherwise.
- No message-wire, federation Hello, cookie or edge change is needed for the card itself. The optional capability in §3.4 uses the existing capability list.

## 4. Relay and shared-source handling

An owner-chosen forwarding host (a small VPS or a family member's machine forwarding a TCP port to the node's Noise listener) is the main way to get a second, independently hosted path. It has a cost at the edge.

**Shared bucket.** Cookies are bound to the source IP (`cookie.rs:180`, `:192`) and every edge budget keys on the accepted socket's source address (`connection.rs:311-337`). Behind a plain forwarder, every client appears as the forwarder's address. They share one `max_per_ip` concurrency allowance, one handshake bucket and one cookie key. A cookie proves nothing about individual clients behind the forwarder, because the forwarder is return-routable by construction. One misbehaving client can use the whole allowance for that path.

**Never trust client-supplied source information.** Forwarding headers, unauthenticated proxy-protocol preambles or any address the connecting side asserts about itself must not change which budget is charged.

| Option | What it does | Costs |
|---|---|---|
| A. Per-relay allowance | The owner lists forwarder source addresses in config; those sockets get larger per-source budgets, still inside `max_handshakes` and `max_pending`. | No per-client fairness behind the forwarder; whoever reaches the forwarder gets the larger allowance; new config surface and validation; misconfiguration (a too-broad address) widens the allowance for unrelated sources. |
| B. Relay-attested client tokens | A BitSov-aware forwarder prepends a short record carrying a per-client value (address or opaque token), authenticated under a key shared only between node and forwarder, and accepted only from configured forwarder sockets. Budgets and cookies then key on the attested value. | A new trust relationship and key to manage; a compromised forwarder can assign arbitrary sources; a new parser before Noise that must fit the existing pre-Noise size and time bounds; plain port forwarding no longer suffices; more test and review surface. |
| C. Accept the limit | Forwarder clients share one source budget. The forwarder may apply its own per-client limits before forwarding. | Abuse through one forwarder throttles honest new peers on that path; the other paths are unaffected; established sessions are unaffected; no node change. |

The choice is an **owner and security decision** (§6.6). Option C needs no code and is compatible with every part of §3, so it is the natural first step; A or B would follow only with their own reviewed design.

What the forwarding path does and does not give:

- It gives a second address to reach the same node key. It does not give anonymity: the forwarder sees client source addresses, timing and the destination node.
- It does not help if the forwarder reaches the node over the same flooded home line. Two names on one host or one network are not independent paths.
- A forwarder carries no owner authority. Noise still proves the node key on every path, and payment admission is unchanged.
- The store-and-forward relay (§2.4) does not provide transparent ingress and must not be described as doing so.

## 5. Test plan (all NOT RUN; to be built with the implementation)

| Case | Pass when |
|---|---|
| v2 round trip (front door and introduction) | issue, encode, parse and verify succeed; order and entries preserved byte for byte |
| Signature-domain confusion | a v2 body signed under the v1 domain, a v1 body under the v2 domain, and a card whose `v` disagrees with its domain all fail verification |
| More than 4 entries, entry over 255 bytes, oversize card or introduction | refused before signature check and before any DNS lookup |
| Duplicate or non-canonical entry | whole card refused |
| `public` entry with a literal local address; `local` entry without per-entry consent | refused / skipped, no dial |
| Reserved `kind` only | card verifies and displays; `open` refuses with no dial |
| Primary unreachable, second entry live | `open` reaches the same pinned key on entry 2 within the total deadline |
| Every entry unreachable or slow | `open` fails within the total deadline; at most one dial per entry; no sockets left open |
| An entry answers with a different key | that entry fails as an unauthenticated refusal; the walk continues; the other key is never accepted |
| Unauthenticated refusal: responder sends `Disconnect` before `HelloAck` (today's closed-mesh path), on entry 1, entry 2 live | walk continues to entry 2 and reaches the expected key; the entry 1 outcome is classified unauthenticated, not "refused by this node" |
| Unauthenticated refusal from a different key: a responder holding another key sends `Disconnect` before `HelloAck` on entry 1 | same as above; nothing about the expected node is recorded from entry 1 |
| Unauthenticated refusal on every entry | `open` fails as "could not reach this node", not as a closed-mesh refusal; at most one dial per entry |
| Authenticated refusal: the expected key, verified (identity binding, Noise static key and `node_id` all checked), then refuses | walk stops; no further entries dialed; outcome "refused by this node". Built only if the wire gains an authenticated refusal; until then the classifier unit test asserts that no current error is classified authenticated |
| Cancellation mid-walk | all sockets and tasks released |
| DNS answer changes between check and dial | dial uses the pinned address only |
| DNS: hostname for a `public` entry resolves only to forbidden addresses (loopback, private, link-local, unspecified, IPv4-mapped IPv6 forms), through an injected resolver | entry refused by `dial_allowed`; a dial recorder shows zero connect attempts to any address of that entry |
| DNS: mixed answer set, allowed address first and forbidden address last (and the reverse order) | whole entry refused; zero connect attempts for that entry, including to the allowed address |
| DNS: entry 1 fails, entry 2 is a hostname resolving to a forbidden address, entry 3 live | entry 2 refused with zero connect attempts; walk continues to entry 3 |
| DNS: every entry resolves to a forbidden address | `open` fails; zero connect attempts in total |
| Mixed fleet: old reader receives v2 | fails closed with a version error; no endpoint dialed |
| Mixed fleet: new reader receives v1 for a node with a v2 marker | refused, including after restart and after card-cache eviction |
| Mixed fleet: new reader receives v1 for a node with no marker | accepted; dials the single endpoint as today |
| v1 with higher `seq` than held v2 | refused by marker before the card cache is consulted |
| Marker outlives a short-lived v2 card: v2 card (or v2 introduction) seen, then a v1 front-door card issued just before that sighting, presented after the v2 card expired but before `now + 7 days + skew` (injected clock) | v1 refused |
| Marker expiry boundary | v1 refused one second before `marker_expiry`; accepted after it (no marker) |
| Marker survives restart | marker written, process restarted with an empty card cache, v1 card refused |
| Marker store unreadable at start-up | reported to the owner; no crash; guarantee for affected nodes recorded as lapsed |
| Downgrade marker table full, some markers expired | expired markers pruned first; no unexpired marker evicted |
| Downgrade marker table full, none expired | the earliest-expiring marker is evicted and counted; v1 for that evicted node is accepted (documented narrowing); v1 for every retained node still refused; table never exceeds `MAX_DOWNGRADE_MARKERS` |
| v2 introduction only: reader has no front-door cache entry and no marker, verifies a v2 introduction, then receives a v1 introduction and a v1 front-door card for the same `node_id` | marker written from the introduction; both v1 cards refused, with no front-door cache entry present at any point |
| Paired v1/v2, v1 arrives first (v1 `seq` N, v2 `seq` N+1) | v2 replaces v1 in the card cache; reader dials v2 entries |
| Paired v1/v2, v2 arrives first | v2 held; v1 stale and marker-refused; v2 still held afterwards |
| Equal `seq` from a non-conforming issuer, both arrival orders | v2 held in both orders; v1 never displaces v2; node stays dialable |
| v2 from an older pair arrives after a newer v1 (v1 `seq` N+2 held, v2 `seq` N+1 arrives) | v2 replaces the held v1; node stays dialable |
| Paired v1/v2 during transition | v2-capable reader uses v2; old reader reaches the first eligible entry |
| Issuer pairing | an issued pair never shares a `seq`; v2 is exactly one above v1; the on-disk floor advances past both |
| Forwarded path with cookies required | clients behind the forwarder complete handshakes; budget charged to the forwarder address; a client-asserted source has no effect |
| Edge regression | the existing cookie and edge tests pass unchanged; no `DosEdgeConfig` field or default changed |
| Mutation: drop per-entry `dial_allowed` | the DNS forbidden-address and mixed-answer rows fail (literal-address shape checks alone must not be what catches it) |
| Mutation: treat an unauthenticated refusal as walk-stopping | the unauthenticated-refusal rows fail |
| Mutation: drop the attempt cap, the downgrade check, the marker refresh (tie expiry to the v2 card), or the v2-over-v1 cache rule | at least one test above fails for each |

Record exact heads, configuration and environment with every result.

## 6. Decisions before implementation (owner / security review)

1. Whether nodes issue a paired v1 card during the transition, and the window length.
2. Which `kind` values the first version supports. Proposed: `direct` only; an onion service stays an explicit later choice, never a default.
3. `MAX_ENDPOINTS` (proposed 4) and how the introduction size limit is met with that many entries; `MAX_DOWNGRADE_MARKERS` (proposed 65,536).
4. Whether v2 links keep the existing `bitsov://front-door#` and `bitsov://introduce#` prefixes or get new ones (clearer error for old readers versus one link format).
5. The total `open` deadline and whether attempts stay strictly sequential or may start staggered.
6. Shared-source handling behind a forwarder: option A, B or C in §4. Proposed: C for the first slice.
7. Whether the home address is advertised at all when a forwarding path exists, and in which position.
8. Who operates forwarding hosts and how a user is told what a forwarder can see.

## 7. What this does not change

- **Edge limits and cookies.** `DosEdgeConfig`, its defaults and validation, `CookieMode` and the cookie format are unchanged. No new cookie implementation is proposed; §5 only re-runs the existing tests as regression evidence.
- **Hash-first admission (#480).** That contract governs what an unpaid peer costs after the handshake; this one governs where a peer can reach the handshake. They pair, and each stays independently testable.
- **Payment and admission.** A card, an endpoint list or a forwarder grants no admission. Paid first contact, the payment gate and closed-mesh refusals are unchanged.
- **Volumetric floods.** Saturation of any single path, and upstream null routing, remain outside what application code can prevent. The remedy is more independent paths, not stronger limits.
