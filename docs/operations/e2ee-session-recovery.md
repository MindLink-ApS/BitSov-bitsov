# Recovering a stuck E2EE session on rc21 and rc22

This page is for operators running the signed `v0.3.0-rc21` or `v0.3.0-rc22`
releases. The code fix is on main as #514 (merge commit `c5d2ce90`). Neither
signed release includes it. Upgrading to a build that includes #514 is the
lasting fix: there, a lost session comes back on the live connection without a
restart. Until then, use the steps below.

This is not disk or seed recovery. For a lost or wiped node, see
[recover](recover.md) and [RECOVERY](../v2/RECOVERY.md).

## What can happen

When the link between two nodes drops and comes back, the nodes set up a new
E2EE session. A paid envelope encrypted before that reconnect can still arrive
afterwards. That stale envelope can leave one node without a session while the
other node keeps its own.

Whether this heals on its own depends on which node has the higher node id:

- If the node that lost the session has the higher id, it usually heals by
  itself within about 30 seconds.
- If the node that lost the session has the lower id, it can stay stuck until
  a new connection between the two nodes is forced. Waiting does not clear it.

Reopening the desktop apps does not heal it. An app talks to its own node;
closing and opening it does not restart the node and does not make a new
node-to-node connection.

## Do not send to test

Do not send a chat message, call or ring, or press a control that admits the
contact again just to see whether the session works.

- A send while the session is gone can be paid for and then fail.
- A send while the other node is offline can fence further spending in that
  app until you use Check pending result.

Read both sides first.

## Read both sessions

These reads change nothing. Run them on each node's host, against that node's
own owner API on loopback (default `127.0.0.1:3141`; see
[QUICKSTART-SIGNET](../QUICKSTART-SIGNET.md) and [reachability](reachability.md)).

Health needs no token:

```sh
curl -sS http://127.0.0.1:3141/api/v1/health | jq '{status, connected_peers, e2ee_sessions, pending_deliveries}'
```

`connected_peers` and `e2ee_sessions` are counts across all contacts. They give
context, not the answer.

The session read needs the owner token. Mint it with `docs/ops/owner-token.sh`
and use the `api` helper, as in
[QUICKSTART-SIGNET step 4](../QUICKSTART-SIGNET.md#4-pair-your-terminal-with-the-node-owner-token).
The helper keeps the token off the command line.

```sh
KONSENSUS_CONFIG=/path/to/konsensus.toml source docs/ops/owner-token.sh
api() { printf 'Authorization: Bearer %s\n' "$OWNER_TOKEN" | curl -sS -H @- "$@"; }
API=http://127.0.0.1:3141/api/v1

api $API/status | jq -r .node_id
api $API/peers/connected | jq .
api $API/sessions/<peer-node-id> | jq .
```

`status` gives this node's id and `peers/connected` the ids of connected
contacts. `<peer-node-id>` is the other node's id. The session read returns
`peer_id` and `active`. You want `active: true` on both nodes.

Node ids are lowercase hex of equal length, so the higher id is the one that
sorts later: `printf '%s\n' <id-a> <id-b> | sort | tail -n 1` prints it. The
table below uses a common home shape, a Raspberry Pi with the higher id and an
Umbrel box with the lower id. The hardware does not set the order; compare your
own ids.

A `pending_deliveries` count left over after a failed paid send does not by
itself mean the session is still stuck. Trust `active` on both sides.

## What to do

| Higher id (Pi) | Lower id (Umbrel) | Meaning | Do |
|---|---|---|---|
| `active: true` | `active: false` | Stuck. Waiting does not clear it. | Restart the higher-id node only (below). |
| `active: false` | `active: true` | Heals by itself. | Wait about 30 seconds and read both again. |
| `active: false` | `active: false` | Heals by itself, as above. | Wait about 30 seconds and read both again. If it then matches the first row, follow that row. |
| `active: true` | `active: true` | Session is up on both sides. | Confirm with one normal message each way. |

If health does not answer, or neither node lists the other in
`peers/connected`, the node is down or unreachable. That is not this problem.
Do not use the restart below until both nodes are up and connected and you
have read `active` on both.

If both nodes read `active: true` but messages are still not read after a
dropped link, that is the separate known limit in
[UPGRADING rc21 → rc22](../UPGRADING.md#rc21--rc22); follow the steps there.

### Stuck: restart the higher-id node only

Do not wait, send, ring or press admit again first.

1. Do not restart during a healthy call.
2. Restart the higher-id node (the Pi in the table) with its existing config
   and data, the way you normally run it. For the example system unit that is
   `sudo systemctl restart bitsov.service`. A home node that starts in LOCKED
   needs its usual unlock before it can reconnect.
3. Wait until both nodes list each other in `peers/connected` and both session
   reads return `active: true`. The Lightning link can take around a minute to
   come back. If `api` answers 401 on the restarted node, mint the token again.
4. Only then send one normal message each way to confirm recovery.

Restarting the lower-id node would also force a new connection. This page
restarts only the higher-id node so the lower-id box is left untouched.

## What it can look like in the app

These signs are hints. The session reads above are the check.

- A send while stuck may come back refused after payment, with advice not to
  send it again.
- On the node that lost the session, the app may show a prompt that the contact
  reconnected and ask you to admit them again. Do not press it as a test; it can
  pay and then fail.
- The contact can still look connected in the app while one node reads
  `active: false`.
