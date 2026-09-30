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
{"v": 1, "room": {"id": "<32 lowercase hex>", "roster": ["<node id>", "<node id>", ...]}, "text": "hello room"}
```

- `id` is 32 lowercase hex (16 random bytes), picked by the room's creator.
- `roster` is 2 to 4 distinct node ids (64 lowercase hex), sorted ascending
  (`MAX_ROOM_MEMBERS`). Sorting makes the roster canonical, so every member
  sees the same bytes; it gives no member any authority.
- `text` is non-empty. `v` is 1. Unknown fields are refused.
- Only chat carries a binding. A chat whose plaintext is a JSON object with a
  top-level `room` key must be a valid binding; any other chat is ordinary.
- The roster is immutable: changing membership means a new room (new id).
  There is no creator authority, no signed roster, no epochs and no kick.

The binding is inside the E2EE plaintext. The envelope of each copy is an
ordinary 1:1 envelope to that member (`Recipient::Node`), so relays and
observers see paid 1:1 chats, not a room.

## Sending

`POST /api/v1/messages/compose` with `is_room: true`, `recipient` = the room
id, `kind` 0 and the plaintext above. The node:

1. Refuses a bad binding before any quote or payment (400 `not_dispatched`,
   `reason` below).
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
**untracked**: no `operation_id`, `retry_allowed: false`. Do not blind-retry
a failed send; resend only to the members whose outcome was not `settled`.

A room chat can also go to one member as a plain 1:1 compose (`is_room`
false, `recipient` = that member). The node checks the binding, that both
ends are in the roster, that the member advertises `room_binding_v1`, and
that there is an E2EE session (a room never pays a first contact), before
any quote or payment. Everything else is the ordinary 1:1 compose: its
`max_total_msat`, operation id and exactly-once journal. A retry of an
operation already journaled replays from the journal without these checks,
so a paid chat stays retryable. This is how the app sends a room: one leg
per member, each capped at the price the owner was shown.

The app shows the cost before Send: the sum of each member's quoted price.

## Receiving

After the payment gate admits a chat and it is decrypted, the node checks
the binding: the sender and this node must both be in the roster. Otherwise
it refuses the chat (withdraws it like any refused message, never shows it)
and answers the sender with `MessageReject` carrying the code, which the
sender sees as a terminal `failed_paid` delivery status. A chat without a
binding is unaffected.

`GET /api/v1/messages` returns `room` (the binding) on each admitted room
chat, and `GET /api/v1/messages?room=<id>` lists only chats bound to that
room: this is the local room thread. The roster shown is the one in the
binding. Ordering is per-sender order plus timestamps; there is no history
backfill.

**Leaving is local:** stop sending and hide the room. Others see that you
left only if you send an ordinary message saying so.

## Refusal codes

| Code | Where | Meaning |
|------|-------|---------|
| `room_binding_invalid` | compose (400), receive | Malformed binding: id, roster size/order/duplicates, empty text, version, unknown field, or `recipient` is not the room id |
| `room_sender_not_member` | compose (400), receive | The sender is not in the roster |
| `room_recipient_not_member` | compose (400), receive | The recipient is not in the roster |
| `room_binding_unsupported` | compose (400 for 1:1; per-member skip in a room) | The member's node does not advertise `room_binding_v1`; nothing paid |
| `room_member_no_session` | compose (400 for 1:1; per-member skip in a room) | No E2EE session with the member; nothing paid |

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
- Nothing binds members to one another: each member's node only checks that
  the sender and itself are in the roster. A sender can show different
  members different text, and a member cannot prove what others received.
- No scale, moderation or group-governance claims. At most 4 members.

## Out of scope

Mutable membership, signed rosters, epochs, MLS, a scribe or relay, history
sync, more than 4 members, public room links. Kinds 910-914 stay reserved
and unused. The admin `POST /api/v1/rooms` path (UUID rooms stored on one
node) is unchanged and separate from bound rooms.

## Evidence

- `konsensus-core` `payloads::room` tests: binding shape, roster order and
  size, refusal codes, membership checks.
- `konsensus-api` `tests/room_binding_tests.rs`: fan-out pays each member its
  own price on its own envelope; members without the advert or a session are
  skipped with nothing paid; bad bindings (and a 1:1 room chat to a member
  without the advert or a session) are refused `not_dispatched` before
  anything is paid; a journaled 1:1 room chat replays without re-checking;
  the receiver admits a binding only with both ends in the roster; the
  `?room=` list; `/status` advertises `room_binding_v1`.
- `konsensus-node` `room_binding_capability_is_advertised_in_the_form_peers_list_shows`.
- `regtest_e2e::real_ldk_regtest_room` (apps A, B, C, D and router R on real
  LDK): A's room chat fans out to B, C and D at 2,001 msat each; a roster
  without A and a 1:1 room chat to a non-member are refused by A's node with
  nothing paid; a member without the advert is skipped at 0 msat; a paid room
  chat from B whose roster lacks B is refused by A (`room_sender_not_member`,
  withdrawn, `failed_paid` on B); channel and budget deltas are msat-exact
  per member.
