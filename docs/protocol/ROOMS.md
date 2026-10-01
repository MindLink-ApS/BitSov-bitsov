# Rooms (MVP)

A room is a fixed roster of 2 to 4 nodes (you and up to 3 contacts), chosen
when the room is created. It is ordinary paid 1:1 chat with an optional
encrypted **room binding**, in the same way a mesh meeting is ordinary 1:1
calls with a `meeting` field on the offer (see `docs/v2/CALLS-PROTOTYPE.md`).
There are no new wire kinds and no room state on any node. This replaces the
broader design in #152 (epochs, signed rosters, kinds 910-914).

## The binding

A room chat is `KIND_CHAT` (0). Its encrypted plaintext is a JSON object:

```json
{"v": 1, "room": {"id": "<64 hex>", "roster": ["<node id>", ...], "salt": "<32 hex>"}, "msg": "<32 hex>", "text": "hello room"}
```

- `roster` is 2 to 4 distinct node ids (64 lowercase hex), sorted ascending
  (`MAX_ROOM_MEMBERS`). Sorting makes the roster canonical, so every member
  sees the same bytes; it gives no member any authority.
- `salt` is 32 lowercase hex (16 random bytes), picked when the room is
  created, so two rooms of the same people are different rooms.
- `id` is 64 lowercase hex and **commits to the roster**:

  ```text
  id = hex(SHA-256("bitsov/room-id/v1\0" ‖ u8(len(roster)) ‖ roster[0] ‖ … ‖ roster[n-1] ‖ salt))
  ```

  with each node id as its 32 bytes and the salt as its 16 bytes
  (`konsensus_core::payloads::room::room_id`). Every node recomputes it on
  compose and on receive and refuses a mismatch (`room_binding_invalid`).
  So a room id names exactly one roster: nobody, the creator included, can
  reuse it with a member added, dropped or swapped. Anyone can compute it,
  so it is not an authority either.
- `msg` is 32 lowercase hex, random per logical room message and the same
  on every member's copy. The sender's node uses it to show its per-member
  copies as one outgoing message.
- `text` is non-empty. `v` is 1. Unknown fields are refused.
- Only chat carries a binding. A chat whose plaintext is a JSON object with a
  top-level `room` key must be a valid binding; any other chat is ordinary.
- The roster is immutable: changing membership means a new room (new salt,
  so a new id). There is no creator authority, no signed roster, no epochs
  and no kick.

The binding is inside the E2EE plaintext. The envelope of each copy is an
ordinary 1:1 envelope to that member (`Recipient::Node`), so relays and
observers see paid 1:1 chats, not a room.

## Sending

`POST /api/v1/messages/compose` with `is_room: true`, `recipient` = the room
id, `kind` 0 and the plaintext above. The node:

1. Refuses a bad binding (including an id that does not commit to the
   roster) before any quote or payment (400 `not_dispatched`, `reason`
   below).
2. For each other roster member, skips with nothing paid (`status`
   `"refused"`, `amount_msat` 0, a `code`) a member whose node does not
   advertise `room_binding_v1` (`room_binding_unsupported`: not connected, or
   an older node) or with no E2EE session (`room_member_no_session`).
3. Pays every remaining member its own quoted chat price through the existing
   room fan-out (`compose_room_member`): one recipient-bound payment and one
   envelope per member per message, under the same grant, caps and bounds as
   any room compose. No dedicated tariff, relay or scribe.

The response lists every other member in `member_outcomes` (sorted by node
id) and the total in `amount_msat`. Like every room compose it is
**untracked**: no `operation_id`, `retry_allowed: false`.

### Retrying a room send

Never resend the whole room. Per member, by `member_outcomes[].status`:

| Status | `amount_msat` | Meaning | Resend to this member? |
|--------|---------------|---------|------------------------|
| `settled` | > 0 | Paid. The message may or may not have arrived. | **No.** Delivery is retried by the node from its queue; a new send pays again. |
| `unknown` | any | The payment (or a re-admission) was dispatched and its outcome is not resolved. | **No.** It may still settle. Wait for reconciliation (the wallet's payment history); an unresolved outcome is never retry permission. |
| `refused` | 0 | Nothing was paid: skipped before any quote (`code` set), or the payment was not dispatched or was confirmed failed. | **Yes**, and only these, with the same `msg` (and the same binding) so the thread still shows one message. |

A resend goes as a 1:1 leg (`is_room: false`, `recipient` = that member) with
an `operation_id` and a `max_total_msat`, so it is exactly-once from then on.
A `settled` or `unknown` member is never resent by the app, whatever the
retry button says.

A room chat can also go to one member as a plain 1:1 compose (`is_room`
false, `recipient` = that member). The node checks the binding, that both
ends are in the roster, that the member advertises `room_binding_v1`, and
that there is an E2EE session, before any quote or payment. **A room never
pays a first contact**: without a session the leg is refused
(`room_member_no_session`), never sent through the paid first-contact
admission. Everything else is the ordinary 1:1 compose: its
`max_total_msat`, operation id and exactly-once journal. A retry of an
operation whose journal shows it paid resends the stored envelope without
these checks, so a paid chat stays deliverable; a journaled operation that
never paid re-enters the paying path and is checked again (session
included) before any quote, and the node refuses a first contact even if
the session disappeared between the check and the payment. This is how the
app sends a room: one leg per member, each capped at the price the owner
was shown.

The app shows the cost before Send: the sum of each member's quoted price.

## Receiving

A room binding is inside the ciphertext, so the node cannot tell a room
chat from a plain one before decrypting it. Every incoming chat is therefore
**staged**: the node places a durable admission hold on it before its paid
acceptance (the same hold as call signals, table `call_admission_hold`).
While held, the chat and its plaintext are invisible to history
(`GET /api/v1/messages`, `/messages/:id`, `/plaintext`, `?room=`), to resync,
and to duplicate-ACK checks (a resend is refused, not ACKed as delivered).

After the payment gate admits the chat it is decrypted, and the node checks
the binding: the id commits to the roster, and the sender and this node are
both in it. Then:

- **Admitted** (valid binding, plain chat, or undecryptable): the hold is
  released and the chat is shown. If the release cannot be written the chat
  stays held and the sender gets `storage error`: fail closed.
- **Refused**: the chat is withdrawn (message and plaintext deleted, receipt
  application-rejected; payment hash and nonce stay burned), never shown,
  and the sender gets `MessageReject` with the code, a terminal
  `failed_paid`. If the withdrawal fails, the hold keeps it hidden.
- **Crash** in between: the hold keeps it hidden; the startup sweep (and the
  periodic one, after 5 minutes) withdraws every leftover hold. A crash
  between acceptance and release therefore costs the sender that paid
  message (`failed_paid` on resend) rather than ever showing an unchecked
  chat.

`GET /api/v1/messages` returns `room` (the binding) and `room_msg` on each
admitted room chat. `GET /api/v1/messages?room=<id>` is the local room
thread, **both directions**: among the newest 1,000 chats this node sent or
received, those bound to that room. The sender's per-member copies of one
message (same `msg`) are one entry: `recipient` is the room id,
`payment_amount_msat` the sum, `copies` lists each member's copy
(`recipient`, `id`, `payment_amount_msat`), and `id`, `ciphertext` and
`payment_hash` are those of the newest copy. `limit` counts entries. `room`
cannot be combined with `peer`. The roster shown is the one in the binding.
Ordering is per-sender order plus timestamps; there is no history backfill.

**Leaving is local:** stop sending and hide the room. Others see that you
left only if you send an ordinary message saying so.

## Refusal codes

| Code | Where | Meaning |
|------|-------|---------|
| `room_binding_invalid` | compose (400), receive | Malformed binding: id shape, the id does not commit to the roster and salt, roster size/order/duplicates, salt, `msg`, empty text, version, unknown field, or `recipient` is not the room id |
| `room_sender_not_member` | compose (400), receive | The sender is not in the roster |
| `room_recipient_not_member` | compose (400), receive | The recipient is not in the roster |
| `room_binding_unsupported` | compose (400 for 1:1; per-member skip in a room) | The member's node does not advertise `room_binding_v1`; nothing paid |
| `room_member_no_session` | compose (400 for 1:1; per-member skip in a room) | No E2EE session with the member; nothing paid (a room never pays a first contact) |

A compose refusal is HTTP 400 with `code: "not_dispatched"` (#115: proven
before any payment, so a client releases its reservation) and the room code
in `reason`; on a per-member skip it is
the outcome's `code`; on receive, the `MessageReject` reason starts with
`<code>:`.

## Capability `room_binding_v1`

A node that checks bindings advertises `Capability::Custom("room_binding_v1")`
in its federation Hello (a connected peer shows `Custom("room_binding_v1")`
in `GET /api/v1/peers`) and lists `room_binding_v1` in its own `/status`
`api_capabilities`. An older node would take the JSON as the chat's text
after it was paid, so the node never pays a member without the advert.
`Custom` is an existing variant, so older nodes still decode the Hello.

## Honesty

- Privacy is pairwise E2EE (Double Ratchet sessions), no more. Each member
  gets their own ciphertext. No MLS, no group key.
- The room id binds the roster, not the members' views: each member's node
  checks the id against the roster and that the sender and itself are in it.
  A sender can still show different members different text (or send some of
  them nothing), and a member cannot prove what others received.
- A receiver refuses a bad binding only after the sender's payment settled:
  the refusal keeps that payment (terminal `failed_paid`). The no-payment
  guarantee is the sender-side preflight on an unmodified node.
- No scale, moderation or group-governance claims. At most 4 members.

## Out of scope

Mutable membership, signed rosters, epochs, MLS, a scribe or relay, history
sync, more than 4 members, public room links. Kinds 910-914 stay reserved
and unused. The admin `POST /api/v1/rooms` path (UUID rooms stored on one
node) is unchanged and separate from bound rooms.

## Evidence

- `konsensus-core` `payloads::room` tests: binding shape, roster order and
  size, the id preimage and its refusal of any other roster or salt,
  refusal codes, membership checks.
- `konsensus-api` `tests/room_binding_tests.rs`: fan-out pays each member its
  own price on its own envelope; members without the advert or a session are
  skipped with nothing paid; bad bindings, a swapped or extended roster under
  a known room id (fan-out and 1:1), and a 1:1 room chat to a member without
  the advert or a session are refused `not_dispatched` before anything is
  paid; a 1:1 room chat without a session spends 0 msat on a real (shared
  mock) ledger and asks for no invoice, with or without an operation id; an
  unpaid journaled room chat whose session went away is refused on retry
  before any quote; a paid journaled one replays without re-checking; the
  receiver admits a binding only with both ends in the roster and a matching
  id; the `?room=` thread lists both directions, our copies once (also on
  SQLite after a real fan-out); `/status` advertises `room_binding_v1`.
- `konsensus-node` `msg_handler::tests::room_chats_stay_hidden_until_their_binding_is_admitted`
  (real receive loop over Noise, SQLite): a valid room chat and a plain chat
  are released and reach the app; a roster without the receiver and a
  swapped roster under the room id are withdrawn, terminal, never listed; a
  failed withdrawal keeps the chat held and hidden, a resend is refused (not
  duplicate-ACKed) and the sweep withdraws it; a failed release withholds an
  admitted chat.
- `konsensus-node` `room_binding_capability_is_advertised_in_the_form_peers_list_shows`.
- `regtest_e2e::real_ldk_regtest_room` (apps A, B, C, D and router R on real
  LDK): A's room chat fans out to B, C and D at 2,001 msat each; B answers on
  its 1:1 leg (2,001 msat) and A's thread shows B's reply and A's message
  once with three copies; a roster without A, a 1:1 room chat to a non-member
  and a swapped roster under the room id are refused by A's node with
  nothing paid; a member without the advert is skipped at 0 msat; paid room
  chats from B whose roster lacks B or does not match the room id are
  refused by A (`room_sender_not_member`, `room_binding_invalid`; withdrawn,
  never listed, `failed_paid` on B); channel and budget deltas are
  msat-exact per member.
