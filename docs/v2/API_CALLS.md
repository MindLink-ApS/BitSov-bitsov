# Open calls by peer

`GET /api/v1/calls?peer=<node-id>` is an owner-scoped, read-only view of the
node's durable call state. It requires a valid owner-subject bearer token with
`read` scope (including an owner's paired app with that scope). Missing or
invalid authentication returns 401; a different subject or missing scope
returns 403.

`peer` is required and must decode as a 32-byte hex node id. Missing, duplicate,
or malformed peer parameters return HTTP 400 with fixed JSON error text:
`{"error":"invalid peer id","code":400}` (the numeric `code` is the generic
bad-request marker; typed refusals such as `not_dispatched` carry a string
`code` instead). Input is never echoed. A valid unknown peer returns `[]`.

The response is an array of at most **4** entries (the per-peer open-call
admission bound), with unresolved reservations first, then call id order.
The bound also applies if the stored data exceeds the admission bound.

```json
[
  {
    "id": "0123456789abcdef0123456789abcdef",
    "state": "ended",
    "direction": "outgoing",
    "unresolved_paid_admission": true,
    "created": 1790000000000,
    "op_id": "9a6b9c52-f45b-400d-8891-080fb382dcad"
  }
]
```

- `id`: the call id, scoped to the requested peer.
- `state`: `reserved`, `ringing`, `live`, or `ended`, aged at read time.
- `direction`: `outgoing` (this node offered) or `incoming` (the peer offered).
- `unresolved_paid_admission`: boolean; conservatively true whenever the call
  retains a pending signal reservation. The read does not reconcile payment
  evidence or release reservations, even when a journal appears terminal.
- `created`: nullable integer, Unix milliseconds. When a pending offer is bound
  to a matching operation journal entry, this is that operation's stored
  `created_at`. Otherwise it is `null`: `call_state` has no creation timestamp,
  and an answer/hangup timestamp is not the call's creation time.
- `op_id`: nullable string, the stored pending signal's operation id, or `null`
  once no operation binding remains in call state. It can refer to an answer
  or hangup rather than an offer. No placeholder strings are returned.

Open means an unexpired reserved/ringing/live call **or any call with a pending
signal**, including calls whose ringing/live deadline and replay tombstone
have expired. Ended/expired calls without a pending signal are omitted.

**The client must fail closed per peer when `unresolved_paid_admission` is
true:** keep blocking re-admission/new paid admission to that peer, even if
`state` is `ended` or metadata is `null`. Expiry does not prove nonpayment.
Only normal operation recovery/settlement can resolve the reservation; GET
never does so. This blocker applies to the requested peer, not unrelated
peers. An empty response is a snapshot, not authorization to bypass the normal
compose/admission checks.

The endpoint uses existing tables without a migration. It does not request
prices, pay, dispatch signals, emit call events, sweep rows, or mutate the
operation journal. See [call protocol and recovery](CALLS-PROTOTYPE.md).

## Contract goldens (app–node)

The responses the app consumes for calls and for the owner-only STUN fields
are pinned as JSON fixtures under
`crates/konsensus-api/tests/fixtures/contract/`, rendered by the live
handlers with fixed inputs and compared field by field by
`crates/konsensus-api/tests/contract_goldens.rs`. The app repo will consume the
same fixtures, so a field added, removed, renamed, retyped or made nullable
on either side fails there and here before it reaches a user.

| Fixture | Request | Status | Contract |
|---|---|---|---|
| `status_stun_own.json` | `GET /api/v1/status` | 200 | Own STUN responder (`[calls] stun_listen`) at a dialable advertised host: `stun_port`, `stun_url` (`stun:<peer host>:<stun_port>`), `stun_source` `own`, `peer_endpoint`, `peer_endpoint_source` `advertised`. |
| `status_stun_configured.json` | `GET /api/v1/status` | 200 | Own responder without a dialable host but a valid `[network] stun_server`: `stun_port`, `stun_url` from the configured server, `stun_source` `configured`, `peer_endpoint_reason` `no_dialable_endpoint`. |
| `status_stun_absent.json` | `GET /api/v1/status` | 200 | No responder, no dialable host, no configured server: `stun_port`, `stun_url`, `stun_source`, `peer_endpoint` and `peer_endpoint_source` are absent; `peer_endpoint_reason` `no_dialable_endpoint`. |
| `peer_call_price.json` | `GET /api/v1/pricing/peers/:id/call` | 200 | The callee's live call price: `peer_id`, `offer_msat` (kind 400, asked of the callee), `signal_msat` (kind 401). |
| `call_invite_accepted.json` | `POST /api/v1/messages/compose` (kind 400, `wait_ack_ms: 0`) | 200 | A paid, dispatched invite: `operation_id` (echoed), `state` `sent`, `accepted` `false` (no acceptance receipt was awaited), `payment_hash`, `retry_allowed`, `max_routing_fee_msat`, `message_id`, `delivered`, `amount_msat`. See [exactly-once operations](EXACTLY-ONCE-OPERATIONS.md). |
| `call_invite_refused_call_id_used.json` | `POST /api/v1/messages/compose` (kind 400) | 400 | A new operation reusing a call id: `error`, `code` `not_dispatched`, `reason` `call_id_used` (see the refusal table in [CALLS-PROTOTYPE.md](CALLS-PROTOTYPE.md)). |
| `calls_open_by_peer.json` | `GET /api/v1/calls?peer=<node-id>` | 200 | Three open calls: an `ended` outgoing call with an unresolved paid admission bound to its journal row (`created` set, `op_id` set) first, then a `ringing` outgoing and a `live` incoming call in id order, both with `created` and `op_id` `null`. |
| `calls_open_by_peer_empty.json` | `GET /api/v1/calls?peer=<node-id>` | 200 | A valid peer with no open calls: `[]`. |
| `calls_invalid_peer.json` | `GET /api/v1/calls?peer=not-a-node-id` | 400 | `{"error":"invalid peer id","code":400}`: the fixed text, with the generic numeric bad-request `code`. |

Each fixture is one envelope:

```json
{ "request": "GET /api/v1/status", "status": 200, "body": { "...": "..." } }
```

`body` is the handler's JSON exactly as served (keys sorted), except for the
masked fields below. Absent optional fields are absent in the fixture too;
`null` stays `null`, so nullability is part of the contract.

### Mask

Node-generated ids and timestamps vary per run, so the test replaces them
with a typed placeholder **after checking their shape**; a mask never hides a
missing field, a `null` that became a value, or a value of another type.
Client-supplied ids (operation ids, call ids) are fixed test inputs and are
kept literally.

| Path (JSON pointer, `*` = every element) | Check | Placeholder |
|---|---|---|
| `/body/node_id`, `/body/connected_peer_ids/*`, `/body/peer_id` | 64 lower-case hex chars | `<hex64>` |
| `/body/lightning_node_pubkey` | 66 lower-case hex chars | `<hex66>` |
| `/body/message_id`, `/body/payment_hash` | 64 lower-case hex chars | `<hex64>` |
| `/body/uptime_secs` | non-negative integer | `<uint>` |
| `/body/*/created` | non-negative integer ≥ 10^12 (Unix milliseconds) | `<unix_ms>` |

### Regenerating

```sh
UPDATE_GOLDENS=1 cargo test -p konsensus-api --test contract_goldens
```

rewrites the fixtures from the live handlers. Review the diff as an API
change, update the table above, and tell the app side: a regenerated fixture
is the contract changing, not the test being wrong.
