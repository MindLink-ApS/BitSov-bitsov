# Browse: a node's public surface, peer to peer (normative)

Status: normative for M3 item 4. It builds on the account layer
(`docs/protocol/ACCOUNT-LAYER.md` §5, where the front-door card is the only
public profile) and on the front-door design (`konsensus-core/src/front_door.rs`).
Every **GAP** marks where the code does not yet meet this spec.

Browse means fetching another node's public surface by its node id: its
profile card, its media and a small site. It works directly between the two
nodes, with no third-party server. Every content read is a paid act, bound to the node
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

## 3. Decision: a 1-sat content read with free metadata preflight

**A porch read costs at least 1 sat (1,000 msat), paid to the node that
serves it. It is single-use and settled before the node answers. There are no
free content reads.** A path-specific availability/price quote is free for
already-admitted contacts (§4); it carries no page body. The owner may charge more. The card advertises the price
(`prices.page_msat`) and the manifest reports the page price. Per-page manifest overrides do not
currently determine the kind-500 payment. The receiving
gate's default price for the web-content kinds is 1,000 msat
(`pricing.web_content_msat`).

### Why not free

- **Doctrine.** Content still requires a fresh payment. The bounded metadata
  exchange only tells an admitted contact whether to buy a read; it grants no
  admission, content, payment proof, or reusable read authority.
- **Sybil resistance.** Node ids cost nothing to mint, so a per-id limit on
  free reads is no limit. A per-IP limit punishes users behind NAT, CGNAT or
  Tor. Payment is the only limiter that needs no identity.
- **Scraping.** Free reads would let anyone harvest a node's site, CV and
  contact hints at zero cost, which is exactly the "free = sell the user"
  pattern the node exists to replace.
- **The card body needs no free lane.** The quote reveals only availability
  and price; a fresh signed card body still requires a paid read.

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

### Quote before payment (`porch_quote_v1`)

`PorchQuoteRequest {request_id, path}` and `PorchQuoteResponse {request_id,
path, status, amount_msat, admission_required}` are Noise control frames, not page envelopes.
Metadata is answered only on a currently privileged connection (paid admission
or the recipient's explicit whitelist). A reader's local admission-payment
marker is not proof of the recipient's whitelist decision. Paths use the
same flat allowlist, containment and size limits as GET. No directory listing,
body, signature, invoice, or payment proof is returned. An absent card, disabled
site, missing file, directory, or zero-byte file returns `NotFound` and no price.
Oversized or unsafe files are unavailable. A metadata check does not read or
validate a file's UTF-8 body.

For `Ok`, the recipient quotes its current kind-500 tariff with the gate's
admission-cost and 1,000-msat Porch floors. This version quotes the public
(no trust discount) tariff. It persists that per-sender/kind offer for five
minutes before returning it, using the existing durable delivery-price store.
Explicit operator prices and chain-aware adjustments determine new quotes.
`web.page_price_msat` is a legacy setting, not a separate charge override.

**Tariff-raise limitation (v1):** a raise does **not** supersede previously
issued delivery offers. A custom client can still clear the kind-500 gate by
paying an older, lower offer before its expiry, without fetching a new quote.
The free porch quote's payment window is five minutes; kind-500 offers from
ordinary price tables/responses can last up to one hour. The store uses the
lowest applicable unexpired sender/kind or category offer. Expiry is inclusive
in whole seconds and is checked against the recipient wallet's settlement
timestamp, not the envelope timestamp. A payment settled within that window
can be delivered for up to one hour after settlement. Restarting or publishing
a higher quote does not revoke the old one. The gate's current admission and
one-sat floors still apply.

Safe supersession is deferred: the shared offer store has no quote provenance,
tariff revision/effective time, or request/payment binding, and chain-aware
prices have no atomic durable raise event. Deleting lower offers or always
requiring the current tariff would also reject already-settled reads awaiting
delivery. Correct supersession needs durable tariff epochs plus a way to bind
payments to offers and distinguish pre-raise settlement from later redemption,
including concurrent updates and restart. Operators must allow the outstanding
offer windows to drain before relying on a raised tariff as a hard minimum.
The regression `porch_tariff_raise_keeps_old_offer_for_payments_before_and_after_raise`
exercises both payment orderings, the expiry boundaries, and the rejection of
already-paid reads if the old offer is deleted. This is a documented limitation,
not a guarantee that custom clients pay the latest quote.

The reader correlates the reply to its own node, the authenticated peer,
request id, and exact path. Pending requests are capped at 256 and removed on
completion, cancellation or timeout (five seconds). The server permits at most
16 quotes per peer per one-second window with at most 256 active peer entries.
Request IDs and paths are bounded at wire decoding to 64 and 128 bytes before
queueing. Responses use the bounded control writer. Unprivileged requests get
only `admission_required: true`, `Forbidden`, and no price; no availability is
looked up. Refusals are separately limited to four per source IP and 32 globally
per second with at most 1,024 source entries, using the existing refusal limiter.
Rate-limited requests receive no response. Quotes never promote a connection or
spend money.

`POST /api/v1/browse/quote {node_id, path, max_routing_fee_msat?}` requires local
read authority and returns `status`, optional `amount_msat` (recipient principal),
`max_routing_fee_msat` and `max_total_msat` (principal plus routing allowance).
Missing pages return HTTP 200 with `NotFound`, null principal and zero total.
A quote is advisory and does not authorize payment.

Every single-peer kind-500 compose, including `/browse/fetch`, obtains a fresh
quote before reserving spend or creating a payment. It pays the returned price,
never the reader's own price or a cached peer fallback. Caller caps, spend grants,
recipient settlement and single-use replay checks still apply. A fresh `NotFound`
refuses fetch with HTTP 404, reason `porch_not_found`, before any payment.
Other unavailable statuses refuse with `porch_unavailable`. Reconnect requires
explicit admission (`readmission_required`). The separate `porch_quote_v1`
capability is advertised in Hello and `/status`; absent capability or timeout
fails closed (`porch_quote_unavailable`), with no legacy paid-fetch fallback.
Both endpoints must be upgraded for this safe fetch flow.
Room compose refuses page and manifest kinds 500, 501, and 510 with HTTP 400,
reason `porch_room`, before quoting, reserving spend, paying, or fan-out.

**Availability race:** quotes do not reserve a content snapshot. Fetch rechecks
after a user previews a quote, but removal, unreadable content, disconnect, or
malicious behavior after the final preflight can still cause a paid failure.
There is no atomic payment/delivery guarantee or automatic refund. Such failures
remain explicitly reported as paid and are never automatically retried. Older
senders that send paid envelopes directly still receive the existing bound
`NotFound` response; this upgrade cannot undo payments they already dispatched.

### Paid content

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

A missing path is normally refused by preflight before paying. A legacy paid
request or a page removed after preflight still gets a bound `NotFound` reply,
including when `[web]` is disabled; its payment is not refunded.

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
    max_routing_fee_msat?}` preflights the path, then pays for one read through compose's own spend
    path, waits for the bound reply, verifies and caches a card, and returns
    the body.
  - `POST /api/v1/browse/quote` previews availability and price without paying.
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
- **App integration.** Apps should use the path-specific quote and distinguish
  recipient principal, routing allowance, and actual paid fees. Older apps may
  still preview cached prices and may treat new prepayment refusals as unknown
  outcomes. See `NOTES-PORCH.md` for the walkthrough app trace.

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

- Missing/empty paths and an unpublished card are refused before payment;
  a quote returns no content or invoice (`porch_quote_reports_availability_and_price_without_paying`,
  `porch_preflight_checks_missing_empty_oversize_and_unsafe_paths`).
- A cached million-msat price cannot override the fresh recipient quote;
  a caller cap still prevents payment and a preview is rechecked at fetch
  (`porch_read_pays_once_and_returns_the_verified_card`,
  `porch_quote_rechecks_deleted_page_and_enforces_payment_cap`).
- A whitelisted connection needs no redundant admission, while an unadmitted
  reconnect spends nothing (`whitelisted_porch_contact_does_not_need_a_second_admission`,
  `reconnect_requires_explicit_knock_before_browse_and_pays_nothing`).
- Wrong-peer/node/path or replayed quote responses cannot complete another
  waiter; oversized fields fail decoding before queueing (`quote_correlation_rejects_wrong_peer_node_path_and_replay`,
  `porch_quote_rejects_oversized_fields_before_dispatch`).
