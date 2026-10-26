# M6: two owners, two nodes, a paid audio call

This is the operator procedure for issue #428 P1. A is the caller; B is the
callee. Media takes **app A → node A → node B → app B**, and the reverse path.
The node-to-node hop uses the existing TCP Noise connection. Each app uses its
own node's paired media socket. The M6 hop-by-hop build must display **“your
node and theirs can hear it”**. App-to-app WebRTC, UDP and STUN are not this
call path. See the [call design](../v2/CALLS-PROTOTYPE.md),
[call API](../v2/API_CALLS.md) and [pairing procedure](../security/pairing.md).

The automated proof below uses real Bitcoin Core, electrs, two LDK wallets,
Noise, SQLite, owner approvals and WebSockets on **regtest**. It sends synthetic
audio-sized frames, not microphone audio. A signet run between different
networks, with the matching M6 app build and at least five minutes of audible
two-way audio, is the separate #428 P3 proof. Record failure honestly if the
matching app engine or payment scheduler is unavailable; regtest cannot certify
microphones, codecs, the remote app tunnel, WAN quality or signet operation.

## Reachability and configuration

Only **B** needs inbound reachability for the node-to-node links. A connects
outward to B and keeps both connections alive; established connections carry
traffic both ways. Remote apps separately need access to their own nodes.

| Listener on B | Transport | Typical port | Purpose |
| --- | --- | --- | --- |
| `[network].listen_addr` | TCP | 9736 | BitSov Noise peer link: signaling and media |
| `[lightning].listening_address` | TCP | 9735 | Lightning P2P: channel and payments |

Forward/allow the two **configured** ports through B's router/firewall; they
must be distinct. A needs outbound access to them and both nodes need access
to their signet chain backends. A needs no inbound port forwarding. Keep the
owner API (normally TCP 3141) local; it is not a public peer listener. An app
on a different machine uses its paired Noise tunnel; that deployment's app
access listener is separate from these two node-to-node ports. Do not expose
the owner HTTP API to make a call work.

Start from [the signet quickstart](../QUICKSTART-SIGNET.md), using signet for
**both** the Lightning and chain backends before funding. For a direct channel,
use the documented `hub_only_channels = false` configuration on ordinary
owner-controlled nodes; a lockable hub-only deployment has different channel
policy. Fund both on-chain anchor reserves and the caller's channel funding.

Edit existing TOML tables in place. On B, choose the price; on A, choose the
outgoing duration limit. Example rehearsal terms:

```toml
[pricing]
mode = "static"
call_block_msat = 23001
call_msat = 1000

[calls]
max_call_minutes = 10
```

`call_block_msat` is the **callee's** per-60-second-block tariff, in msat, and
must be positive (default 10000). The existing invoice floor, chain-aware
pricing and trust discount can affect the payable amount; static pricing and
no discount make a rehearsal easiest to reconcile. Offer and answer/hangup
fees are separate. `max_call_minutes` is the **caller's** cap: default 60,
allowed 1–240. Restart to apply changes. A reservation pins the cap and price
for that call, so changing config does not resize an existing hold.

The ordinary offer still uses the paired messaging per-act ceiling (6000
msat, including routing fees). The example sets `call_msat = 1000` so it fits
even with the default 5000-msat routing-fee allowance. The default 10000-msat
offer does not fit that ceiling; raising the call-block grant alone does not
authorize it. The block reservation has its own call authority.

Use locally supplied variables for configurations, endpoints and peer keys.
Do not copy real machine addresses, filesystem locations or owner identities
into public proof. Start each node using its own configuration:

```sh
konsensus start --config "$NODE_CONFIG" --owner-control
```

Privately verify the other owner's node ID/safety number. Add B's reachable
peer endpoint on A with the owner console:

```sh
konsensus peer add --config "$NODE_CONFIG" \
  --node-id "$B_NODE_ID" --addr "$B_PEER_ENDPOINT" --label "call peer"
```

B must also admit A. On B, add an inbound-only contact to the **owner TOML
configuration**, then restart B. Replace the two placeholders below with A's
verified ID and the sentinel printed by
`python3 -c 'import ipaddress; print(str(ipaddress.IPv4Address(0)) + ":0")'`:

```toml
[[peers]]
node_id = "<A_NODE_ID>"
addr = "<INBOUND_ONLY_SENTINEL>"
label = "call peer"
auto_connect = false
```

The unspecified-address, port-zero sentinel is accepted in configuration and
is never dialed. `peer add` deliberately rejects it, so use configuration for
this inbound-only side. A must initiate/reconnect. Do not use A's transient
inbound source port as its listening address. Neither admitting a peer nor
opening a channel grants free signaling or media.

Open a private A→B Lightning channel through the owner API following the
quickstart's fee preview and confirmation procedure. Use B's **Lightning
pubkey** and LN endpoint, not its BitSov node ID or peer port. Wait until both
ends report the channel usable. Give B enough outbound liquidity above its
channel reserve to pay an answer and a terminal notification (an explicitly
approved push or real A→B invoice payment can do this). A's outbound capacity
must cover the whole reservation plus setup and fees.

## Checks before dialing

1. Record the exact node SHA on each host and the app SHA/build on each device.
   Check that both nodes include N1 #453, N2 #454 and N3 #460. For this
   integration branch, `e710bf0` is the merge beneath P1; it is not a substitute
   for recording the actual running HEAD. Verify both apps use node-routed M6
   audio with direct WebRTC disabled.
2. On both nodes check `GET /api/v1/status`: expected node identity, real LDK,
   `money_ready: true`, advancing signet chain height. Verify signet in
   `GET /api/v1/payments/funding-address`. Check `peers/connected` and
   `payments/channels`; keep the original Noise connection established.
3. Pair each app to its own node and approve a bounded, live `spend` grant.
   A needs the reservation, offer and possible termination fee; B needs answer
   and termination spending. A read-only pairing cannot dial or open media.
   Use [owner approvals](../v2/OWNER-APPROVALS.md) and
   [spend budgets](../SPEND_BUDGET_GRANTS.md). Send a paid preflight chat to
   establish/verify the encrypted signaling session and any first admission.
4. Inspect B's advertised `kind:404` price in
   `GET /api/v1/pricing/peers` on A. The `/pricing/peers/:id/call` endpoint
   reports **offer/signal** prices, not the block tariff. The compose path
   asks B afresh for kind 404 before reserving/paying. The app must show B's
   payable block price, the cap, the total reservation and fees, and receive
   explicit price/cap consent before dialing.
5. Ensure the grant's total, per-call, recipient and rolling spend limits cover
   `max_call_minutes × (block price + enforced per-block routing-fee ceiling)`.
   One active channel must have enough known outbound capacity after other
   call holds. This is a local liquidity check, not a guarantee of routing.
   An unresolved operation or hold must be reconciled, never cleared by
   deleting the ledger or using a new operation ID to retry an uncertain pay.

## Run, renew, and stop

Use the M6 app's Dial and Answer controls. For protocol diagnosis, these are
the corresponding calls to **each app's own node**, using a paired `spend`
token and a stable unique `operation_id` for each action:

| Action | Compose kind | JSON plaintext |
| --- | --- | --- |
| A dials B | 400 | `{"v":1,"call_id":"<32 lowercase hex>","media":"audio","sdp":"<app offer>"}` |
| B answers A | 401 | `{"v":1,"call_id":"<same id>","sdp":"<app answer>"}` |
| A pays B for block 0 | 404 | `{"call_id":"<same id>","seq":0}` |
| A renews | 404 | `{"call_id":"<same id>","seq":1}` (then 2, 3, …) |
| Either hangs up | 403 | `{"v":1,"call_id":"<same id>","reason":"hangup"}` |

The endpoint is `POST /api/v1/messages/compose`, with `recipient`, `kind`,
`plaintext` (the JSON encoded as a string), `operation_id`,
`max_total_msat` and `max_routing_fee_msat`. Caps must match owner consent;
they must not silently increase on retry. The offer pays for ringing only.
Answer starts a 30-second block-zero payment window and **does not admit
media**. Verify both media sockets refuse before block 0 settles.

After settlement each app opens
`/api/v1/calls/<call_id>/media?peer=<other node id>` on its own authenticated
node connection. The WebSocket subprotocols are `bitsov.v1` and
`bitsov.jwt.<paired token>`; do not log that header. One binary message is
`seq` (four bytes, unsigned big-endian) followed by the codec payload. Each
direction has its own increasing sequence. There is one owner socket per
call. Confirm microphone audio arrives in both directions.

Observe `GET /api/v1/calls?peer=<other node id>` on A: the reservation appears
at dial, `next_block_seq` becomes 1 after block 0, and `spent_msat` rises while
`remaining_msat` falls. Schedule each next 404 at `next_block_due_ms`, normally
20 seconds before `paid_until_ms`. Blocks buy contiguous 60-second intervals
anchored to the answer; paying late does not move the anchor. A single call
hold counts once toward the payment-count breaker, not once per block.

For cutoff proof, leave both nodes and media sockets connected and stop only
the caller app's **404 renewal loop**. Do not send Hangup, close the channel,
revoke the whole grant or disconnect a node: those test different stop paths.
If the app cannot pause renewals independently, record that limitation and
use the regtest harness for this fault injection. Media may continue through
the ten-second grace after the final paid boundary. B must then record
`unpaid`, close media, and attempt its paid 403 notification. A must release
the unspent reservation once. The media router rechecks admission every second;
allow that bounded teardown interval after state expiry, not another block.
Notifications are best effort: local cutoff
does not wait for their delivery. Capture the exact failure if a funded,
connected B cannot deliver its notice.

Automatic Unpaid/duration-cap notices use bounded node authority, with a
1000-msat total cap and zero routing-fee allowance; they do not debit the
paired grant. A higher signal price or a route requiring a fee can therefore
prevent the notice despite available funds. Manual app hangup uses the app's
grant. Reconcile these wallet payments separately from the reservation.

To check the cap cheaply, start a **new** call with A configured for one
minute. Pay block 0. `next_block_due_ms` becomes null, seq 1 is refused with
`call_duration_cap`, and A ends at the paid boundary with `duration_cap`,
without renewal grace. Restore the rehearsal cap before a five-minute run.

## Stop reasons and refusals

| Reason | Meaning and response |
| --- | --- |
| `hangup` | One participant deliberately ended the call. Unspent funds release; settled blocks remain paid. |
| `declined` | Callee declined the offer. No media; setup fees already settled remain paid. |
| `busy` | Callee declined because it cannot take the call. Retry later with fresh consent and a new call ID. |
| `timeout` | The offer was not answered within its 60-second ringing window. |
| `failed` | The call failed, including definite payment failure. Inspect the operation receipt before retrying. |
| `unpaid` (Unpaid in the app) | Block 0 missed its 30-second window, or a renewal missed the final paid boundary plus ten-second grace. Media ends locally even if the notice cannot be paid. |
| `duration_cap` | Caller reached its pinned paid-duration limit. Media ends at the final paid boundary. |
| `payment_failed` | Client/payment error, not a separate wire hangup enum. A definite failure ends the call; an ambiguous operation stays journaled until reconciled. |
| `call_price_changed` | B's new block price exceeds the reserved ceiling. Call ends; a new call needs fresh consent. |
| `call_price_unknown` | No fresh answer from B for the required tariff. Nothing should be paid; check connection/admission/readiness. |
| `call_liquidity_insufficient` / `call_liquidity_unavailable` | Capacity is too small or cannot be established. Resolve liquidity/readiness before dialing. |
| `budget_exceeded` / `price_cap_exceeded` | Approved limits do not cover the request. Inspect the structured reason and ask the owner for appropriate terms. |

Early/duplicate/out-of-order 404s are refused; they do not buy another block.
Use the same operation ID and identical payload to recover an uncertain
operation. Do not interpret a missing HTTP response as a failed payment.

## Capture proof without publishing private data

Record node A SHA, node B SHA, both app SHAs, toolchain, network, UTC start/end,
config values, sanitized commands, pass or exact failure, paid block count,
amount/fee for each block, media frame counts/order (or audible WAN evidence),
last paid boundary, stop time/reason and the released remainder. In each node
checkout:

```sh
git rev-parse HEAD
rustc --version
```

Use the authenticated API helper from the quickstart with a **paired token**
when observing that app's `pair/grant`. Keep headers out of shell tracing and
logs. Save `calls` reservation snapshots while live and grant `used_msat`
before dial, after reservation, after blocks and after termination.
`GET /api/v1/payments` contains wallet payment records; select only the relevant
amounts, directions and statuses. Retain hashes privately if needed to match
receipts, and publish aliases. Account separately for preflight, admission,
offer, answer and hangup payments.

Ended calls without pending operations disappear from `GET /api/v1/calls`.
On A, capture the final receipt within 24 hours from the owner-only
`pairing/clients.json` beneath the configured data directory. Set
`PAIRING_LEDGER` locally to that file and `CALL_ID` to the observed call ID.
**Read only**; never publish the whole file. This extracts only accounting:

```sh
jq --arg call "$CALL_ID" '
  [.grants[] | .budget.call_reservations // {} | .[]
   | select(.terms.call_id == $call)
   | {max_call_minutes: .terms.max_call_minutes,
      per_block_msat: .terms.per_block_msat,
      per_block_fee_msat: .terms.per_block_fee_msat,
      reserved_msat: .terms.reserved_msat,
      spent_msat, released_msat, closed}]
' "$PAIRING_LEDGER"
```

Require exactly one matching receipt, `closed: true`, and
`reserved_msat = spent_msat + released_msat` once all operations are resolved.
Repeat after several maintenance ticks: receipt and grant usage must stay
unchanged. A pending/ambiguous debit remains held until its outcome is known;
report it as unresolved rather than claiming a release. Finished receipts
are bounded and pruned, so capture promptly. Remove local paths, owner names,
addresses, tokens, seeds, preimages and private payloads from public artifacts.

## Automated regtest proof

Provision the existing harness's hash-pinned Bitcoin Core and Esplora electrs
fixtures as described in [regtest e2e](../regtest-e2e.md). Set `BITCOIND_EXE`
and `ELECTRS_EXE` privately to those executables. No fixture is downloaded by
the runner. From the repository root:

```sh
cargo test -p konsensus-core -p konsensus-node -p konsensus-api \
  -p konsensus-message -p konsensus-storage -p konsensus-pricing
scripts/regress/two_node_paid_call_e2e.sh
cargo clippy -p konsensus-core -p konsensus-node -p konsensus-api \
  -p konsensus-message -p konsensus-storage -p konsensus-pricing \
  --all-targets --features konsensus-node/regtest-e2e -- -D warnings
```

The wrapper uses `regtest_e2e.sh` and its process-group timeout/cleanup. There
are no shortened block clocks. Allow several minutes after compilation.
Exit 77 means fixtures were missing and the tests only compiled: **not a
pass**. The manual/nightly `three-node-paid-e2e` workflow provisions fixtures,
runs both call scenarios and requires both `M6 CALL PASS` markers. It retains
`paid-call.log`; review/redact raw logs before posting outside CI.

Expected accounting at B's test price of 23001 msat and zero direct-channel
routing fees:

| Scenario | Cap | Paid blocks | Reserved | Spent | Released |
| --- | ---: | ---: | ---: | ---: | ---: |
| Stop renewing → Unpaid | 5 minutes | 3 | 115005 | 69003 | 46002 |
| Duration cap | 1 minute | 1 | 23001 | 23001 | 0 |

All amounts are msat. These totals exclude separately paid signaling and
preflight traffic. Passing requires real settlement at B's price, no media
before block 0, ordered 160-byte frames both ways across the paid intervals,
cutoff on both owner sockets, and repeated cleanup leaving the receipt and
grant usage unchanged. The fixture keeps call rows, price answers and payment
proofs on their production paths; it never inserts a synthetic paid call.
