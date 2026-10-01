# Choose your chain source

BitSov can use your own Bitcoin Core (pruned or full) for both embedded LDK
Lightning and chain height, headers, fees and transaction confirmation. MindLink
does not run a default chain server. This is step 1 of the chain-source work:
existing Esplora configurations and fresh `init` defaults remain unchanged;
onboarding selection, Neutrino and Electrum are later steps.

## Own Bitcoin Core

Run Bitcoin Core with RPC enabled (`server=1`). A pruned node can use
`prune=550` (MiB minimum); choose a larger retention window for time spent
offline. Keep RPC bound to loopback or a private, authenticated tunnel: the RPC
transport is HTTP. Do not expose it to the Internet. No `txindex` is required.

Replace the node's `[chain]` stanza (absolute paths recommended):

```toml
[chain]
backend = "bitcoind"
rpc_host = "127.0.0.1"
rpc_port = 8332
cookie_file = "/home/bitsov/.bitcoin/.cookie"
```

This also selects Core for `[lightning] backend = "ldk"`; its Esplora URLs and
fallback are ignored. Keep the Lightning `network` aligned with Core. The RPC
host is a bare hostname or IP, not a URL. Core's usual RPC ports are 8332
(mainnet), 18332 (testnet), 38332 (signet) and 18443 (regtest). Network-specific
cookies live in Core's corresponding data subdirectory.

Cookie authentication is preferred. Grant the BitSov process read access to
Core's cookie without making it world-readable. Alternatively, omit
`cookie_file` and set:

```toml
rpc_user = "bitsov"
rpc_password_file = "/home/bitsov/secrets/bitcoin-rpc-password"
```

The password file contains only the password, optionally followed by a newline.
Use restrictive file permissions (for example 0600); configure the matching
credentials in Core, preferably using Core's `rpcauth` facility. Inline
`rpc_password`, cookie values and credential-bearing URLs are rejected. Never
put passwords in command arguments. Specifying both authentication modes is an
error. The chain provider rereads credentials per request; **restart BitSov after
Core rotates its cookie**, because the vendored LDK RPC client captures it at
startup.

Both Core modes fully validate blocks. Headers survive pruning. LDK needs the
blocks since its last sync: retain enough history for outages and wallet recovery;
a node missing required pruned blocks needs that history restored before it can
sync. Pruning is not archival recovery. Core may have no fee estimate on a fresh
node or regtest; the provider reports that explicitly rather than inventing one.

Txid-only confirmation lookup first uses Core's mempool/transaction index. Without
`txindex`, it searches the last 288 retained blocks, so recent confirmations work
on pruned nodes too. A transaction outside that window or already pruned returns
**unavailable**, not “unconfirmed.” Archival arbitrary-txid lookup requires a full
node with `txindex=1`. There is no fallback to a public explorer.

## Privacy and status

Authenticated `GET /api/v1/status` includes:

```json
{"chain_view":{"backend":"bitcoind","trust_level":"trustless","host":"127.0.0.1"}}
```

“Trustless” describes validation by your own Core, including pruned Core; it is
not a connectivity or sync guarantee. The separate height/readiness fields report
availability. If you point RPC at someone else's Core, you are trusting that
operator; this setting assumes you control the node.

Esplora remains supported and reports `backend: "esplora"`,
`trust_level: "third_party"`, and the selected provider's hostname. A public
Esplora can link queried wallet outputs and private channel funding to your IP.
Your own Core removes that explorer query disclosure; it does not hide Bitcoin
P2P traffic or make Lightning anonymous. Chain host details appear only in
owner status, not public health. Chain selection changes no identities, contacts,
payment admission rules or custody arrangement.
