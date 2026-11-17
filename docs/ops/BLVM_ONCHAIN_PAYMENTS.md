# BLVM on-chain chat payments

BitSov chat can be admitted on a BLVM payment path. Everything else stays on Lightning. Calls, file sends, rooms, web replies, and grants do not accept a BLVM proof.

Default config is Lightning-only. `[blvm] enabled` defaults to false. A node that never loads `blvm-payment` keeps today's Lightning gate.

## Paths

| Path | Proof | What pays for a chat message |
|---|---|---|
| 1 | Lightning `payment_hash`, `preimage`, `amount_msat` | One settled Lightning payment. JSON and signable bytes match rc24. |
| 3 | `blvm_on_chain_session` | One on-chain prepay, then a per-message debit sequence. |
| 2 | `blvm_covenant` | A CTV covenant proof. Mesh hop for this path only when `mesh_ctv = true`. |

Path 3 and path 2 are opt-in through `[blvm] allowed_paths`. Listing them does not turn off the Lightning gate. Calls still require Lightning.

## What the receiver must run

The receiver's blvm-node must have the `blvm-payment` module loaded. The node RPC method names are `verifyonchainpayment`, `verifyonchainpaymentbytx`, `verifycovenantproof`, and `getpaymentstate`. A bare node returns "Method not found". Startup probes `getpaymentstate` and refuses to start with that reason. The first chat proof fails the same way if the probe was skipped.

`verifyonchainpaymentbytx` only succeeds when this node already stores the BIP70 outputs for that payment request. Share the payment request onto the receiver's `blvm-payment` before the sender broadcasts. A request that exists only on the sender's node does not verify here.

`pending` may call `verifyonchainpaymentbytx`. `not_found`, `request_not_found`, `reorg_pending`, `tx_mismatch`, `output_mismatch`, `underpaid`, and `failed` do not. A result with no `amount_sats` is a refusal.

## Chat admission

The gate checks settlement, then records the debit, then consumes the nonce. A session debit sequence is single-use for that transaction. Replaying it fails and does not consume a new nonce. An underpay fails. `reorg_pending` does not advance the debit.

A path-3 proof without `session_debit_seq` is a session open, not a chat message.

The refusal names the chain state: `reorg_pending`, `underpaid`, `tx_mismatch`, `output_mismatch`, or payment request not found. A missing `blvm-payment` module is reported as method not found.

## Sending

Chat compose checks `blvm_on_chain_sessions` for the recipient. An open session with enough remaining balance reserves the admission price, assigns the next debit sequence, and sends a path-3 proof. No session means the message stays on Lightning. Calls do not consult this table.

The owner opens that row on the node that holds the BIP70 request:

- `POST /api/v1/blvm/chat-session/request` creates the request (`receive`).
- `POST /api/v1/blvm/chat-session` verifies the transaction once and stores the session (`spend`).
- `GET /api/v1/blvm/chat-session/:node_id` reads it (`read`).
- `GET /api/v1/blvm/chat` reports whether this node can open one.
- `GET /api/v1/status` includes `blvm_chat`. It is false while `[blvm]` is off.

The app node panel shows the same flag. When it is true, the owner can create the request, store the verified transaction, and read the remaining balance from that panel. The app does not broadcast the transaction and does not accept a session the node refused to verify.

Confirm does not poll. Call it again after the payment is visible to this node's `blvm-payment`. A request stored only on the other node still does not verify here.

The price is held in `blvm_pending_outbound_debits` until the peer acknowledges. ACK keeps the spend. A terminal refusal puts the price back. A debit still pending after one day is rolled back and counted in `bitsov_blvm_stale_debit_cleanup_total`. An ACK that arrived without the commit is committed by that same sweep instead of released.

## Schema

Migrations 42–45 add `payment_proof_json`, `blvm_session_debits`, `blvm_on_chain_sessions`, and `blvm_pending_outbound_debits`. Version 34 stays unused. A binary that does not know version 42 refuses a database that has applied it.

## Mesh

Path 3 hop payment is bincode variant 1, `OnChainSettlement`, matching blvm-mesh `070645f`. Path 2 is variant 2, `InstantSettlement`, which a default blvm-mesh build does not include. Set `mesh_enabled = true` and `mesh_ctv = true` together or the node refuses to start. Do not send variant 2 at a default mesh.

`send_packet` does not wait on a hello. Discovery does. Sequence is assigned inside blvm-mesh. The BitSov request does not set it. Field order is destination, payload, payment_proof, protocol_id, ttl.

## Example

See `examples/konsensus-blvm-onchain-only.toml` for path 3 chat plus Lightning for everything else.
