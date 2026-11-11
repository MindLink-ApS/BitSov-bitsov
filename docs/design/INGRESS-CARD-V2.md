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
- `:183-208` `FrontDoorCard` has one `endpoint: String` and one `reach`, with `deny_unknown_fields`. `:210-228` `FrontDoorFields` likewise.
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
- A refusal from the right key (for example `Rejected` from a closed mesh) stops the walk: the node answered, and other paths would get the same answer.
- No fallback outside the list: not to a previously cached endpoint, a STUN result, an older card or any address the signed card does not name.

### 3.4 Downgrade rule

The risk is not forgery: an old v1 card is genuinely signed by the node and, until it expires (at most 7 days for a front door), still verifies. Presenting it to a reader steers that reader to one endpoint, possibly the one under load. Because Noise still pins the key, the harm is availability, not impersonation.

Rule: **a v2-capable verifier never accepts a v1 card for a `node_id` it knows has published v2.** It knows this from any of:

1. a verified v2 card for that `node_id` in its card cache;
2. a persisted downgrade marker, `node_id → (highest v2 seq seen, marker expiry)`, written when a v2 card verifies. It survives cache eviction and restart, is bounded in count like the card cache, and expires no earlier than the newest v2 card it records;
3. optionally, a capability the peer advertises inside an authenticated session (`front_door_card_v2`), which sets the same marker. It is learned only after a connection, so it protects later opens, not the first one.

Sequence numbers: v1 and v2 front-door cards from one node share one monotonic `seq` space (the existing floor). A v1 card with a `seq` at or below the held v2 `seq` is already stale under today's cache rule; the marker additionally refuses a v1 card with a higher `seq`.

Introductions carry no `seq` and live 10 minutes. A v1 introduction is refused only through a marker or cache entry from the same `node_id`'s front-door card.

Residual risk, stated plainly: a reader with no prior knowledge of a node cannot tell a stripped v1 card from a node that never upgraded. That first-contact case is limited to availability and ends at the v1 card's expiry or the reader's first v2 sighting.

### 3.5 Transition

- **Old readers** refuse v2 cards with `UnsupportedVersion` or `Malformed`. They fail closed and show no endpoint.
- **New readers** accept v1 cards from nodes without a downgrade marker, and dial the single endpoint as today.
- **Publishing nodes** issue v2 by default once built. During a transition window the node may also issue a paired v1 card with the same `seq` whose `endpoint` equals the first eligible v2 entry, so old readers still reach the owner's preferred path. Whether to issue that pair, and for how long, is decision §6.1.
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
| An entry answers with a different key | that entry fails; the walk continues; the other key is never accepted |
| Right key refuses (closed mesh) | walk stops; no further entries dialed |
| Cancellation mid-walk | all sockets and tasks released |
| DNS answer changes between check and dial | dial uses the pinned address only |
| Mixed fleet: old reader receives v2 | fails closed with a version error; no endpoint dialed |
| Mixed fleet: new reader receives v1 for a node with a v2 marker | refused, including after restart and after cache eviction |
| Mixed fleet: new reader receives v1 for a node with no marker | accepted; dials the single endpoint as today |
| v1 with higher `seq` than held v2 | refused by marker |
| Paired v1/v2 during transition | v2-capable reader uses v2; old reader reaches the first eligible entry |
| Downgrade marker table full | bounded; eviction policy documented and tested |
| Forwarded path with cookies required | clients behind the forwarder complete handshakes; budget charged to the forwarder address; a client-asserted source has no effect |
| Edge regression | the existing cookie and edge tests pass unchanged; no `DosEdgeConfig` field or default changed |
| Mutation: drop per-entry `dial_allowed`, the attempt cap or the downgrade check | at least one test above fails |

Record exact heads, configuration and environment with every result.

## 6. Decisions before implementation (owner / security review)

1. Whether nodes issue a paired v1 card during the transition, and the window length.
2. Which `kind` values the first version supports. Proposed: `direct` only; an onion service stays an explicit later choice, never a default.
3. `MAX_ENDPOINTS` (proposed 4) and how the introduction size limit is met with that many entries.
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
