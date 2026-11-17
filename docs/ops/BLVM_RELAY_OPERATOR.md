# BLVM relay operator

A relay that forwards BitSov chat over blvm-mesh uses the hybrid sender: direct Noise when the peer is connected, mesh otherwise.

Pin blvm-mesh at `070645f` (`security/sequence-socket`). Do not pin a dirty worktree.

## Config

```toml
[blvm]
enabled = true
rpc_url = "http://127.0.0.1:8332/"
mesh_enabled = true
mesh_ctv = false
allowed_paths = ["lightning", "blvm_on_chain_session"]
```

`mesh_ctv = false` is the default mesh build. Path 3 (`OnChainSettlement`, bincode variant 1) is the hop payment. Path 2 stays off. Turning on `blvm_covenant` while `mesh_enabled = true` requires `mesh_ctv = true`. The node refuses the other combination at startup.

`enabled = false` does not construct the RPC client. BLVM chat proofs are refused with `payment_path_not_allowed`.

## Module and payment requests

Load `blvm-payment` on the node behind `rpc_url`. Startup calls `getpaymentstate`. "Method not found" means the module is not registered.

The receiver must already hold the BIP70 outputs. Verify does not reach across to the sender's node to fetch them. The owner creates that request with `POST /api/v1/blvm/chat-session/request` and, after the transaction is visible on this node, stores the outbound session with `POST /api/v1/blvm/chat-session`.

## What stays on Lightning

Calls, file sends, rooms, web replies, and grants. The relay does not gain a BLVM arm for those.

## Schema

This binary applies migrations 42–45 once, on SQLite and on Postgres. `recorded_at` is written by the node. The SQL does not use SQLite `strftime`. Version 34 is unused. Opening a database that has a higher version than this binary fails closed.
