# Browse: a node's public surface, peer to peer (normative)

Status: normative for M3 item 4. It builds on the account layer
(`docs/protocol/ACCOUNT-LAYER.md` §5, where the front-door card is the only
public profile) and on the front-door design (`konsensus-core/src/front_door.rs`).
Every **GAP** marks where the code does not yet meet this spec.

Browse means fetching another node's public surface by its node id: its
profile card, its media and a small site. It works directly between the two
nodes, with no third-party server. Every read is a paid act, bound to the node
that serves it. Bitcoin pays for the read. It never names the node, lists it
anywhere, or records who reads whom.

## 1. The three layers of a public surface

| Layer | What | Where it comes from | Cost to the reader |
|---|---|---|---|
| **Doorstep** | The signed front-door card (≤ 16 KiB) | A link, a QR code, a forward inside a paid message, or a cache | Free. Reading a card you hold never contacts its node. |
| **Porch** | A fresh card, site pages, and later media | The owner's node, over kinds 500, 501 and 510 | One paid read per request (§3) |
| **House** | Everything else: messages, files, calls | The owner's node | The usual per-kind prices, once the peers are in contact |

The doorstep is free because it costs the owner's node nothing: the card
travels without the node. The porch costs sats because each read makes the
owner's node do work.

## 2. Who can read, and how a node id resolves

A porch read is an ordinary paid envelope. It needs a live Noise connection
**and** an E2EE session with the owner's node.

- **Contacts** already have both.
- **Strangers** Knock first. A Knock is the existing paid first contact
  (admission). A porch read **never pays admission implicitly**. Without a
  session, the requester's own node refuses the read before anything is paid
  (`porch_knock_first`). A stranger's first read therefore costs one admission
  plus one read. With default prices that is about 3 sats.

A node id resolves to a reachable node in this order:

1. The peer registry: a contact whose address you saved.
2. A card you hold. `POST /api/v1/front-door/open` dials its endpoint without
   privilege, then you Knock.
3. Nothing else. There is no DHT, no directory, no gossip announcement and no
   name registry. If you do not hold a card or an address for a node id, you
   cannot browse it. You get its card out of band.

## 3. Decision: a 1-sat porch read, not a free read

**A porch read costs at least 1 sat (1,000 msat), paid to the node that
serves it. It is single-use and settled before the node answers. There are no
free reads.** The owner may charge more. The card advertises the price
(`prices.page_msat`) and the manifest can set a price per page. The receiving
gate's default price for the web-content kinds is 1,000 msat
(`pricing.web_content_msat`).

### Why not free

- **Doctrine.** No payment, no packet. A free read is an unpaid packet that
  the node answers, which turns the membrane into a wall with a hole in it.
- **Sybil resistance.** Node ids cost nothing to mint, so a per-id limit on
  free reads is no limit. A per-IP limit punishes users behind NAT, CGNAT or
  Tor. Payment is the only limiter that needs no identity.
- **Scraping.** Free reads would let anyone harvest a node's site, CV and
  contact hints at zero cost, which is exactly the "free = sell the user"
  pattern the node exists to replace.
- **The card needs no free lane.** The card already travels free as a link.
  The only thing a free read would add is freshness. Freshness is not worth an
  unpaid lane, because a card expires after 7 days anyway.

### Why 1 sat

- `caps::payable` already floors every paid act at 1,000 msat on the sender
  side. Many Lightning nodes refuse HTLCs under 1 sat
  (`htlc_minimum_msat = 1000`), and sub-sat outputs are dust. The receiver
  gate's old default of 50 msat was below what any sender actually paid.
- It is cheap enough that browsing your contacts is a thoughtless act, and
  dear enough that a flood pays the victim (see the analysis below).

### DoS and workload analysis

This analysis assumes 1 BTC = $100,000, so 1 sat = $0.001, and cloud egress
at $0.12/GB.

Work the owner's node does for one read:

| Step | Cost | Before or after payment |
|---|---|---|
| Issue a Lightning invoice | 1 invoice record plus a signature | Before. Only for privileged (admitted) peers (#100) |
| Settle the HTLC | One commitment update with the channel peer | Payment |
| Gate the envelope | Ed25519 verify, SHA-256 preimage, settlement lookup, replay insert | After |
| Read the file and encrypt it with the ratchet | ≤ 256 KiB, under 1 ms | After |
| Egress | ≤ 256 KiB | After |

Revenue compared with egress:

| Policy | Revenue per read | Egress per read | Result |
|---|---|---|---|
| Old defaults: 50 msat, 4 MiB page | $0.00005 | $0.00048 | Egress costs about 10 times the revenue. The node loses money on every read. |
| **This spec: 1 sat, 256 KiB cap** | $0.001 | $0.00003 | Revenue is about 32 times the egress. Every read pays for itself. |

Cost to an attacker: forcing 1 GB of egress out of a node takes 4,096 reads,
which is 4,096 sats, about $4.10. **All of it lands in the victim's wallet.**
Under a free policy the same flood costs the attacker nothing.

The expensive part of a 1-sat read is the Lightning round trip, not the bytes.
Invoice issuance is the one step that happens before any money moves. It is
already limited to privileged peers, so an unpaid stranger cannot make the
node issue invoices for reads.

## 4. Wire

- **Request.** Kind 500 `PageRequest {request_id, path, method: "GET"}`. It
  is E2EE and paid at the recipient's web-content price.
- **Reply.** Kind 501 `PageResponse {request_id, status, content_type, body,
  cache_seconds}`. The reply is bound to the request (`web_reply.rs`). Its
  payment proof reuses the request's hash and preimage at `amount_msat = 0`,
  and `references` names the request id. The requester's gate accepts a reply
  only against its own outstanding paid request: same peer, expected kind,
  within 5 minutes. The gate then consumes that request. A reply never mints a
  payment.
- **A bound reply admits nothing.** The requester paid; the replying node did
  not. The requester's node therefore does not promote the replying
  connection to privileged, and does not count the reply as an admission.
- **Manifest.** Kind 510 works the same way (paid request, bound reply). Its
  `free_paths` field must stay empty: nodes never fill it in, and requesters
  ignore it.

Porch paths:

| Path | Served from | Content type |
|---|---|---|
| `/front-door.json` | The owner's **published** card, in memory. It is served even when `[web]` is disabled, because publishing a card is consent to share it. | `application/json` |
| `/<name>.md`, `/<name>.txt` | `[web] content_dir`: flat names only, the same rule the owner's page API enforces | `text/markdown`, `text/plain` |
| Anything else | Nothing. That includes subdirectories, hidden files, other extensions, `front-door.seq` and `*.tmp`. | `NotFound` reply |

A paid read for a path that does not exist still gets a `NotFound` reply,
including when `[web]` is disabled. The reader paid for an answer, and an
honest "nothing here" is that answer.

Porch content is markdown or plain text, rendered locally by the reader. A
remote node never supplies HTML or scripts. Links on a card are never fetched
automatically.

## 5. Caching and relaying signed cards

A card is self-verifying: anyone may cache it, host it or pass it on, and no
holder can forge one.

**The node's cache** (`konsensus-core/src/card_cache.rs`):

- It holds only cards whose signature verifies. They are keyed by node id.
- A higher `seq` replaces a lower one. A lower or equal `seq` is ignored and
  reported as stale, so a node cannot roll a reader back below a card the
  reader already holds.
- An expired card stays in the cache and is shown "as of" its date. It is
  never dialled: `open` requires a fresh card.
- It holds at most 512 cards, 8 MiB in the worst case. When it is full, the
  card that expires first is evicted.
- A porch read of `/front-door.json` fills the cache. The reader's node checks
  that the card's `node_id` is the node it paid. A card for any other node is
  refused (`porch_card_mismatch`) and not cached.

**Relaying by peers:**

- **v1:** forward a card link inside a paid message. The sender pays the
  recipient, exactly as for any message.
- **Later:** a peer may serve cards it holds from its own porch at
  `/cards/<node_id>.json`, paid to that peer. A relaying peer can withhold a
  card or serve an old `seq`, but it cannot forge one. This is **off by
  default and needs two opt-ins**: the card's owner ("share with contacts",
  from the mesh-browse design) and the relaying owner. Serving someone's card
  reveals that they are in your address book, and contacts are private.

**Identity stays off-chain.** A card is signed by the node key. No card, seq
or read is anchored on-chain, and there is no name registry. `seq` is a
counter, not a block height.

## 6. Size limits

| Item | Limit | Where |
|---|---|---|
| Whole card, including its signature | 16 KiB | `front_door::MAX_CARD_BYTES` |
| Inline avatar / media thumbnail / media entries / site titles | 8 KiB / 4 KiB / 12 / 20 | `front_door.rs` |
| Porch request path | 128 bytes, one flat name | `payloads::content::MAX_PORCH_PATH_LEN` |
| **Porch reply body** | **256 KiB per read** | `payloads::content::MAX_PORCH_BODY_BYTES`. The owner's `max_page_size` is clamped to it. |
| Manifest | 1,000 pages | `content_server::MAX_MANIFEST_PAGES` |
| Cached cards | 512 | `card_cache::MAX_CACHED_CARDS` |
| Media (later) | Avatar ≤ 512 KiB, fetched by its BLAKE3 hash in 256 KiB chunks, one paid read per chunk | GAP |

The transport's 16 MiB frame limit is never approached.

## 7. Rate limits

- **On the serving node, payment is the rate limit.** It resists Sybils and
  it pays for itself (§3). A read that has been paid for is never refused for
  rate: that would take money without giving service. An owner who wants
  fewer reads raises the price.
- **Before payment:** invoice issuance is limited to privileged peers
  (existing, #100). Unpaid strangers get no invoices, no reply and no price
  table.
- **On the reading node:**
  - One porch read may be in flight per peer. A second one is refused before
    paying (`porch_busy`).
  - Spend is bounded by the caller's spend authority, the same authority as
    compose: a console grant, a device-key relation intent or a budget grant.
  - The reply wait is 20 s. A read that got no reply is reported as paid with
    no reply (`porch_timeout`, with the amount paid). It is never retried
    automatically, because every retry pays again.
- **GAP.** There is no per-peer throttle on invoices issued for porch reads.
  A privileged peer can request invoices as fast as it can pay them. That is
  bounded by its money, not by a limit.

## 8. Privacy and honesty

- The owner learns which node read which path, and when. That is the nature
  of a payment bound to the recipient, and it is the same as a web server's
  log. The app must say so.
- Lightning routing nodes see a 1-sat HTLC and its timing, never the content.
  Noise and the Double Ratchet keep plaintext off the wire.
- No third-party servers are involved: no CDN, no DNS registry, no directory,
  no relay.
- **Not claimed:**
  - anonymity for readers;
  - location privacy for owners (the endpoint is on the card);
  - availability while the owner's node is offline (there is no relay in v1).

## 9. What v1 ships, and the gaps

**Built:**

- **Server:**
  - The published card is served at `/front-door.json`.
  - Only flat `.md` and `.txt` pages are served.
  - The reply body is capped at 256 KiB.
  - A request for a missing path gets `NotFound`, including when `[web]` is
    off.
- **Price:** the defaults for `pricing.web_content_msat` and
  `web.page_price_msat` are 1,000 msat (they were 50).
- **Reader:**
  - `POST /api/v1/browse/fetch {node_id, path, max_total_msat?,
    max_routing_fee_msat?}` pays for one read through compose's own spend
    path, waits for the bound reply, verifies and caches a card, and returns
    the body.
  - `GET /api/v1/browse/cards` lists the cached cards.
  - `/api/v1/status` advertises `porch_read_v1`, and so does the federation
    Hello (peers list it as `Custom("porch_read_v1")`), so a reader's app
    offers a paid read only to an owner that answers one.
- **Fix:** a bound web reply no longer promotes the replying connection and
  no longer counts as an admission.

**GAPs:**

- **Media.** Binary media fetched by hash, in chunks, is not built.
  `ContentServer` serves text only.
- **Stranger reads without a Knock.** Reading a stranger's porch without
  admission would need sealed requests to the card's key. It is not built and
  needs an ADR, because it asks the node to do work before anyone has paid.
- **Card relay by peers** (§5) is not built.
- **The card cache lives in memory only.** It is lost on restart.
- **Invoice throttle** (§7): no per-peer throttle on porch invoices.
- **App.** Discover still offers paste plus Knock only. A "Browse" view that
  calls `/browse/fetch` is not built. Until it is, the app must not imply that
  it fetches content across nodes.

## 10. Invariants (tested)

- A porch read pays the owner exactly its web-content price, once. The bound
  reply moves no money and does not promote the replying connection
  (`browse_two_node::porch_read_pays_once_and_returns_the_verified_card`).
- Without an E2EE session, a read is refused before any invoice or payment
  (`browse_two_node::porch_read_without_a_session_pays_nothing`).
- A card fetched from a node is cached only if its signature verifies and its
  `node_id` is the node that was paid. A lower `seq` never replaces a higher
  one (`card_cache::tests`).
- The serving node answers only the card path and flat `.md`/`.txt` pages. It
  never serves `front-door.seq`, hidden files, subdirectories or HTML
  (`content_server` tests). No reply body exceeds 256 KiB.
