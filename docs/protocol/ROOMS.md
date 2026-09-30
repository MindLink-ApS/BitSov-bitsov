# Paid rooms (group chat) — protocol design

30 Sep 2026 · M3 item (d) · Design only.  
Sources: `pm/BITSOV-NORTHSTAR.md`, `pm/projects/bitsov/research/PROTOCOL-VS-APP-AUDIT.md` (d), mesh meetings (`pm/projects/bitsov/research/MESH-MEETINGS-DESIGN.md`, genome #138 / #141, `docs/v2/CALLS-PROTOTYPE.md`), reserved kinds 910–914 in `konsensus-core::kind`.

**One line:** a room is a **signed, invite-only roster of contacts**; every room act is **one or more ordinary paid, recipient-bound 1:1 deliveries** (the meetings pattern), never a free multicast and never a public graph.

## 0. What exists today (honesty)

| Layer | Reality |
|---|---|
| Wire kinds `KIND_ROOM_CREATE/INVITE/JOIN/LEAVE/UPDATE` (910–914) | **Dead code** — defined in `kind.rs`, never composed or handled elsewhere. |
| App "Rooms" | Lists rooms from the local node; a send uses `is_room` and fans out. |
| Node behaviour | **Admin REST** (`handlers/rooms.rs`) stores `rooms` / `room_members` on **one** node. A "room send" is `compose_room_member`: up to `MAX_ROOM_FANOUT_MEMBERS` (256) **individually paid 1:1 chat** messages (`compose.rs`). Paid-ness per hop is clean; **membership is not peer protocol**. |

Until this design ships, the app must not imply peer-negotiated groups (M3 honesty: "coming soon" / fan-out copy).

## 1. Doctrine constraints (non-negotiable)

From the north star:

1. **Payment is the connection.** Every room packet that moves over the mesh is admitted by a **settled, recipient-bound, single-use** Lightning payment for that act and that payee. No free "room channel".
2. **Bitcoin anchors energy, never identity or the social graph.** A room id is not a Bitcoin-derived identity; membership is keys + local policy.
3. **Contacts are private. Invite-only is local policy.** The protocol never publishes a global directory of rooms or members. Who is in a room is known only to members (and whoever they choose to tell out-of-band).
4. **No central server.** No room home node that other members must trust for membership or message fan-out as *authority*. A member's own node is their store of record for what *they* received.
5. **Moderation is local immune policy**, never a global censor.

Biology check: tissue = bounded community that federates via paid synapses; membrane at each 1:1 edge.

## 2. Shape (reuse meetings)

Mesh meetings proved a doctrine-clean pattern: **a group is a fixed roster + shared id; the mesh is N 1:1 legs; the node keeps almost no group state**.

Rooms copy that skeleton for **async text**:

| Meetings (voice) | Rooms (chat) |
|---|---|
| `meeting.id` + ordered `roster` (2–4) on the offer | `room.id` + signed `roster` epoch (MVP: small N) |
| Each unordered pair is one **call leg** (400…) | Each (sender → member) delivery is one **message leg** (914 or chat-with-room binding) |
| Earlier-in-roster places the leg (deterministic payer) | **Sender pays every other live member** for that send (see §4) — same "1:1 payee" semantics as today's fan-out |
| Node enforces roster/leg order; no meeting store | Node enforces roster signature + membership epoch on compose/receive; **no authoritative room DB across nodes** |
| Capability `call_meeting_v1` | Capability `room_v1` (advertise before sending kinds 910–914) |

**Do not invent a new money primitive** (no "pay once, flood free"; no shared wallet; no SFU billing) for MVP.

### 2.1 Room identity

- `room_id`: 32-byte random id (hex), minted at create. Not a NodeId.
- `roster_epoch`: u64, increments on membership change.
- `roster`: ordered list of member NodeIds (creator first for MVP).
- `roster_sig`: ed25519 over canonical bytes (`room_id ‖ epoch ‖ roster ‖ …`) by the **roster authority** (MVP: creator's node key; later: threshold / rotation — open decision §9).
- Members verify the signature before accepting INVITE/JOIN/UPDATE under that epoch.

Out-of-band share form (optional): `bitsov://room/<token>` carrying the signed roster blob — never a wire packet by itself (same class as invites / front-door cards).

## 3. Membership and invites

### 3.1 Create (`KIND_ROOM_CREATE` = 910)

- Local act on the creator's node: mint `room_id`, epoch 1, roster `[creator]`, sign.
- **No mesh packet required** to "exist". Optional: creator may notify no one.
- Replaces admin `POST /api/v1/rooms` as the *protocol* create; REST may remain a local UX shim that only mutates **this** node's view until peers sync via paid invites.

### 3.2 Invite (`KIND_ROOM_INVITE` = 911)

- Creator (or later: a member with invite right — open decision) sends a **paid 1:1** invite to a **contact** who already has an E2EE session (same contact gate as calls / meetings).
- Payload: signed roster at epoch E (or E+1 provisional), room display name (local hint only), invite nonce.
- Payee: the invitee. Price: invitee's room/control tariff (or a dedicated `room_invite_msat`); asked live like other kinds.
- Invite is **not** admission to the mesh whitelist beyond normal contact rules; it is admission to *this room's roster* after JOIN.

### 3.3 Join (`KIND_ROOM_JOIN` = 912)

- Invitee accepts: sends paid JOIN to the **inviter** (MVP) carrying the same `room_id` / epoch / nonce.
- Inviter (and optionally each existing member — MVP can defer) updates to epoch E+1 roster including the newcomer, signs, and distributes the new signed roster via paid 1:1 **roster update** deliveries (could be JOIN ack payload or a thin UPDATE; if we keep kinds minimal, bake the new roster into JOIN success fan-out as 914-class control).
- Until JOIN settles, the invitee is not a member; messages to the old roster do not include them.

### 3.4 Leave (`KIND_ROOM_LEAVE` = 913)

- Leaver sends a **paid** LEAVE to each remaining member (or, MVP: to the roster authority only, who then fans a signed epoch bump — see §4.2 tradeoff).
- Preferred doctrine-clean default: **leaver pays each remaining member** one LEAVE (symmetric to sender-pays-each for messages). Cost shown before Leave.
- After LEAVE, removers bump epoch, resign roster without the leaver, and stop accepting UPDATE/chat for the old epoch from that key.

### 3.5 Who may invite / kick

- **MVP:** only the creator (roster authority) invites and removes.
- **Later:** member-invite with creator co-sign, or rotating authority — must not create an unpaid broadcast path.
- **Kick:** authority signs epoch without the kicked id and delivers paid notice to remaining members; kicked peer learns by LEAVE-equivalent notice or by failed verifies. No global ban list.

## 4. Who pays whom per message

### 4.1 Default (recommended): sender pays each member

For a chat send with live roster `R` (excluding self):

1. App/node expands to `|R|−1` **independent** compose operations (same journal / reserve→pay→commit discipline as 1:1 and as today's `compose_room_member`).
2. Each leg: kind **`KIND_ROOM_UPDATE` (914)** (or `KIND_CHAT` with a mandatory `room: {id, epoch, roster_hash}` binding — prefer **914** so room traffic is explicit and priced separately).
3. Payee: that member. Price: **that member's** advertised price for 914 (live quote), never the sender's tariff.
4. Partial success is allowed (meetings-style partial mesh): UI shows per-member delivered / unpaid / unreachable; no automatic unpaid retry that double-pays (same `operation_id` rules).

This matches:

- North star (recipient-bound payment per act),
- Current honest fan-out money,
- Meetings "each edge is a 1:1 paid act".

**Cost UX:** before Send, sum all-in ceilings for every member (as Join/Invite ceilings in meetings). Cap roster size so the sum stays human (see §7).

### 4.2 Alternative (deferred): relay member with fan-out and receipts

One member (or a rotating "scribe") receives **one** paid UPDATE from the sender, then pays to fan out to others, collecting **paid receipts** back.

| Pros | Cons |
|---|---|
| Sender pays ~1× instead of N−1 | New money semantics ("pay on behalf"); scribe can censor or delay; receipt protocol; griefing |
| | Conflicts with "no central server" if the scribe becomes de facto required |

**Not MVP.** Document only as a future opt-in for large N, with explicit owner consent and still **per-recipient settlement** on the fan-out legs (scribe pays members; sender paid scribe). No free flood.

## 5. Ordering and history

### 5.1 Ordering

- **No global total order** without a leader (leader ⇒ social/authority gravity). MVP:
  - Each message carries `sender`, `sender_seq` (monotonic per sender per room), `room_id`, `epoch`, `sent_at`.
  - Recipients display by `(sent_at, sender, sender_seq)` locally; ties broken deterministically.
  - Concurrent messages from different senders may appear in different orders on different nodes — acceptable for chat (Signal-like per-sender order).
- Optional later: vector clocks or a **paid** consensus not in scope.

### 5.2 History and sync

- Each node stores only envelopes **it** paid to receive or sent.
- Catch-up: member A may **request** missing `(sender, seq)` ranges from member B via a **paid** control fetch (new sub-kind or 914-with-flag) — B's price, recipient-bound. No free backfill.
- New joiner does **not** automatically get full history; MVP: empty history + optional paid catch-up from inviter (explicit).

### 5.3 Encryption

- MVP: same E2EE as 1:1 sessions **per leg** (already required for contacts). Room plaintext is not a separate MLS stack in MVP (open decision §9 for true group E2EE).
- Roster metadata is signed but not secret from members; do not put social graph in unsigned gossip.

## 6. Leaving, mute, moderation (local policy)

| Act | Protocol | Local only |
|---|---|---|
| Leave | Paid LEAVE + epoch bump (§3.4) | Remove room from UI |
| Mute room / member | — | Local: suppress notifications; still accept paid mail if policy allows |
| Block member | — | Local refuse receive / don't invite; may combine with LEAVE |
| "Report" | — | Signed **local** abuse evidence (northstar immune), never a global ban API |
| Delete for everyone | **Not supported** | Sender may tombstone locally; others keep their paid copies |

No room admin can remotely wipe another node's store or unpaid-mute the mesh.

## 7. Bounds (MVP)

Aligned with meetings' small-N honesty:

| Bound | Proposal | Rationale |
|---|---|---|
| Members | **2–16** (start **≤8** if UX cost scary) | Sender-pays-N; meetings capped at 4 for media |
| Simultaneous rooms | App-defined | Node: reuse per-peer / compose bounds |
| Fan-out concurrency | Reuse `MAX_ROOM_FANOUT_CONCURRENCY` | Already battle-tested on admin path |
| Payload | Existing message size limits | 914 carries room binding + chat body |
| Epoch gap | Refuse UPDATE if epoch ≪ local (stale) | Anti-replay of old rosters |

## 8. Wire kinds (activate the reserved range)

| Kind | Role |
|---|---|
| 910 CREATE | Optional mesh announce; or local-only + out-of-band card |
| 911 INVITE | Paid 1:1 to invitee |
| 912 JOIN | Paid 1:1 to inviter / authority |
| 913 LEAVE | Paid 1:1 to each remaining (or authority — prefer each) |
| 914 UPDATE | Paid 1:1 chat (or roster bump) under `room_id`+`epoch` |

Capability: `room_v1` on Hello / `api_capabilities` (same pattern as `call_meeting_v1` #141).

Pricing: category Control (900–999) or dedicated room prices; **live quote per payee** on compose.

## 9. Open decisions for Rasmus

1. **Roster authority:** creator-only (MVP) vs rotating / multi-sig.
2. **LEAVE fan-out:** leaver pays all vs authority fans signed removal (fewer payments, more authority).
3. **Kind 914 vs chat+room binding:** prefer distinct 914 for clear pricing and refusal codes.
4. **Group E2EE (MLS):** defer vs require before any "private room" marketing.
5. **Large-N scribe relay (§4.2):** never / later opt-in.
6. **Admin REST rooms table:** deprecate after `room_v1`, or keep as local cache of protocol rooms only.
7. **App create UX:** ship "+ New room" only after MVP protocol, or keep honesty copy until then.

## 10. Comparison summary — meetings vs rooms

| | Mesh meetings #138/#141 | Rooms (this design) |
|---|---|---|
| Purpose | Realtime A/V | Async text |
| Group glue | `meeting` on call offer | Signed `room` roster epochs |
| Edge unit | Paid call signal 400–403 | Paid 911–914 (or chat legs) |
| Who pays | Earlier roster → later | **Sender → each member** (message); invitee/inviter rules for 911/912 |
| Node group state | None | Verify signature/epoch; local membership set |
| Partial mesh | Yes | Yes (partial delivery) |
| Public graph | No | No |
| Size | ≤4 | ≤8–16 MVP |

**Reuse:** contact gate, live price query, journaled `operation_id`, all-in ceilings UI, capability adverts, "show cost before act", refuse-before-reserve on invalid roster/epoch.

## 11. Size estimate

| Slice | Size | Notes |
|---|---|---|
| Full protocol (create→invite→join→chat→leave, epoch verify, capability, tests, app UX) | **L** | Matches audit "L"; multi-PR |
| Core node+API only (no polished app) | **M** | Kinds, pricing, compose verify, regtest |
| Design + honesty copy only | **S** | This doc + app "coming soon" (done separately) |

Rough genome effort if sequencing after meetings: **~1–2 weeks** focused for MVP §12 (node+minimal app), assuming meetings/call payment machinery stays stable.

## 12. MVP slice (shippable)

**Goal:** three contacts create a room, invite/join with payment, exchange text where the sender pays each other member, leave cleanly — no admin-only membership.

1. **Node:** `room_v1` capability; verify signed roster on compose/receive for 911–914; refuse unknown/stale epoch (`room_roster_invalid`) before reserve.
2. **Money:** sender-pays-each for 914; paid 911/912/913 as in §3–4; reuse compose journal.
3. **Local store:** per-node room list + epoch + member set (replace *authority* of SQLite admin membership for `room_v1` rooms).
4. **App:** create / invite / join / send / leave with cost ceilings; hide or dual-run old admin fan-out behind a flag.
5. **Tests:** unit (roster sig, epoch); integration (3-node invite/join/chat/leave, partial delivery); pricing refuse paths.
6. **Out of MVP:** MLS, scribe relay, >16 members, kick UI polish, history backfill marketplace.

**Retire path:** when `room_v1` is default, admin `POST /rooms` membership becomes a local mirror or is deprecated; dead kinds 910–914 become live.

## 13. Non-goals

- Public or discoverable rooms / social feed.
- Free or prepaid "room subscriptions" that admit unpaid packets.
- Server-side moderation, global blocks, or delete-for-everyone.
- Replacing 1:1 chat or meetings.
- Claiming location privacy or scale beyond small invite-only groups.

## 14. References

- North star: MindLink-Private `pm/BITSOV-NORTHSTAR.md`
- Audit: `pm/projects/bitsov/research/PROTOCOL-VS-APP-AUDIT.md` item (d)
- Meetings: `pm/projects/bitsov/research/MESH-MEETINGS-DESIGN.md`; PRs BitSov-bitsov #138 / #141; `docs/v2/CALLS-PROTOTYPE.md`
- Code today: `kind.rs` 910–914; `handlers/rooms.rs`; `compose.rs` `compose_room_member` / `MAX_ROOM_FANOUT_*`
