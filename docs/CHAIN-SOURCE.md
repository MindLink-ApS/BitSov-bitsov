# Choose your chain source

BitSov can use your own Bitcoin Core (pruned or full) for both embedded LDK
Lightning and chain height, headers, fees and transaction confirmation. MindLink
does not run a default chain server. Existing Esplora configurations and fresh
`init` defaults remain unchanged;
Electrum is also supported with an explicit server. Onboarding selection and
Neutrino are later steps.

## Esplora fallbacks

`[chain] api_url` remains the primary chain/pricing source. Set
`api_url_fallback` to an optional second Esplora URL; the existing
`esplora_url_fallback` spelling is also accepted. With no explicit chain
fallback, the node appends the configured `[lightning]` LDK `esplora_url` and
`esplora_url_fallback`, removing duplicate endpoints. Old configurations retain
their primary and deserialization defaults; no new provider or key is added.

Chain reads and LDK share each endpoint's HTTP 429 cooldown, including the
bounded Retry-After policy. Height lookups try the fallback on errors, unusable
heights or a stalled primary. External Esplora sources remain `third_party` in
owner status. If no nonzero height is available, pricing returns `not_ready`
and the node does not publish a height-zero price table. A sender keeps a
cached peer offer only while its block and time validity still hold.

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

## Electrum server

Owners running electrs or Fulcrum (for example on Umbrel or Start9) can select
that server for both chain queries and embedded LDK:

```toml
[chain]
backend = "electrum"
server_url = "tcp://192.168.1.20:50001"
operator = "own"
```

Use the Electrum port exposed by your server, not its Esplora HTTP port.
`server_url` is required; there is no default server or discovery. Only
`ssl://host:port` and `tcp://host:port` with an explicit nonzero port are accepted.
Credentials, paths, queries and fragments are rejected. Missing or invalid URLs
fail startup. An unreachable server fails startup or leaves sync stalled;
**there is no switch to Esplora**, including for post-broadcast verification.
The Lightning Esplora primary/fallback settings are ignored for this backend.
Keep Lightning's `network` aligned with the Electrum server's Bitcoin network.

Plain `tcp://` is permitted only for `localhost`, loopback IPs, RFC1918 private
IPv4 addresses, IPv6 unique-local addresses (including private/loopback IPv4
mapped into IPv6). LAN hostnames such as `umbrel.local` require
`ssl://`; use a private IP literal for plaintext LAN access. Public addresses and
other hostnames require `ssl://`, which verifies the server certificate and
hostname. A self-signed certificate is not automatically trusted. Plain LAN TCP
is not encrypted and can be observed or altered on that network. Tor/`.onion`
Electrum servers are unsupported until a proxy setting exists; `.onion` hosts
are rejected at configuration validation for both `ssl://` and `tcp://`.
For TLS to an IPv6 server, use a DNS hostname: the pinned Electrum client's TLS
parser does not support IPv6 literals, so `ssl://[IPv6]:port` is rejected at
startup. Private and loopback IPv6 literals remain supported with `tcp://`.

`operator` accepts `own` or `third_party`; omission defaults to `third_party`,
even for a loopback or private address. With `operator = "own"`, owner status is:

```json
{"chain_view":{"backend":"electrum","trust_level":"own_node","host":"192.168.1.20"}}
```

For Electrum, `own_node` means **you declared that you run this server**.
`third_party` means no such declaration was made (or you explicitly chose it).
Neither label proves ownership, full block validation, correct responses, the
server's network, connectivity, or synchronization. Electrum remains
server-trusting in both cases. It sees queried script hashes and transactions,
which let it link the addresses and outputs the wallets watch; TLS protects
transport, not this disclosure to the operator. Using your own server removes
that disclosure to a third-party chain server only if you actually control it.

Height, headers, fees and transaction lookups use this same Electrum endpoint.
Confirmation lookup fetches the transaction and its output script histories
(the standard protocol supported by electrs and Fulcrum); it does not require
the optional verbose-transaction extension. Missing history or unavailable
transactions return an error rather than an assertion that they are unconfirmed.
An available server tip is not proof that it is current. No keys are sent to the
server, and chain selection does not change custody.

## Privacy and status

Authenticated `GET /api/v1/status` includes:

```json
{"chain_view":{"backend":"bitcoind","trust_level":"own_node","host":"127.0.0.1"}}
```

`own_node` means you configured Bitcoin Core and is an assumption that you control
it. BitSov does not prove that Core validates blocks, that you own it, or that it
is connected or synchronized. If you point RPC at someone else's Core, you trust
that operator. The separate height/readiness fields report availability.

**Status compatibility:** `chain_view.trust_level` was renamed from `trustless`
to `own_node`. App clients matching this value must update; `third_party` is
unchanged.

LDK wallet sync failures for Esplora, Bitcoin Core and Electrum appear in owner
status, including during initial sync:

```json
{"chain_sync":{"state":"stalled","since":1790899200,"last_error_kind":"sync_failed"},"money_ready":false}
```

`since` is Unix seconds at the first failed attempt for the currently failing
wallet in this process. Retries preserve it, and a successful sync clears that
wallet's failure. A failure of either wallet keeps the diagnostic stalled. This
diagnostic does not gate money operations: `money_ready` retains its running,
post-startup wallet sync and timestamp freshness checks. `sync_failed` is a fixed,
non-secret kind: it does not diagnose pruning versus an unreachable RPC or Electrum server. No remote error text, credentials or paths
are returned. Restore required block history or chain-server access and let LDK retry.
`chain_sync: null` means no observed wallet sync failure (or a backend without
this diagnostic), **not** proof of synchronization. Use `money_ready` for money
readiness. Diagnostics reset on restart; existing freshness checks still apply.

Esplora remains supported and reports `backend: "esplora"`,
`trust_level: "third_party"`, and the selected provider's hostname. A public
Esplora can link queried wallet outputs and private channel funding to your IP.
Your own Core removes that explorer query disclosure; it does not hide Bitcoin
P2P traffic or make Lightning anonymous. Chain host details appear only in
owner status, not public health. Chain selection changes no identities, contacts,
payment admission rules or custody arrangement.

## Optional authenticated Esplora (OAuth client credentials)

A paid or private Esplora API can be selected explicitly. It remains a
`third_party` chain source: paying for access does not provide local validation.
Status shows the active chain source's hostname only. No paid provider or
credentials are enabled by default, and configurations without `credentials_file`
keep their existing behavior.

Example for Blockstream Explorer API:

```toml
[chain]
backend = "esplora"
api_url = "https://enterprise.blockstream.info/api"
credentials_file = "/home/bitsov/secrets/chain-api.toml"
# Optional: use an Esplora endpoint you have chosen as the fallback.
api_url_fallback = "https://your-fallback.example/api"

[lightning]
backend = "ldk"
network = "bitcoin"
esplora_url = "https://enterprise.blockstream.info/api"
credentials_file = "/home/bitsov/secrets/chain-api.toml"
esplora_url_fallback = "https://your-fallback.example/api"
```

The credentials file is separate TOML (these are placeholders, not real keys):

```toml
token_url = "https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token"
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
```

Create it privately, owned by the account running BitSov, with **exactly mode
0600** (`chmod 600 /home/bitsov/secrets/chain-api.toml`). Startup refuses insecure
permissions, another owner's file, symlinks, directories, or malformed contents.
Use HTTPS URLs without userinfo, query parameters or fragments. Redirects are
not followed. Keep secrets out of the node config, URLs and command arguments.
Each stanza's credentials apply only to that stanza's primary endpoint; fallback
requests never receive those credentials. Restart after replacing the file.

The token request POSTs `client_id`, `client_secret`,
`grant_type=client_credentials`, and `scope=openid` as form fields. Tokens remain
in memory. A request refreshes the token when it enters its refresh window
(30 seconds before expiry for a 300-second token); an idle node fetches a fresh
token on its next request. A 401 forces one refresh and one retry. Concurrent
requests share the cache within each client and coalesce refreshes. The vendored
LDK transport applies live headers to wallet sync, fees, funding checks and
broadcasts, including client clones; it does not require a restart every five
minutes. Authentication errors and HTTP error bodies are redacted.

Chain requests use the existing ordered fallback list when token acquisition,
refresh, or API requests fail, and report the endpoint that actually supplied
the data. Authenticated LDK sources use the configured LDK fallback both during
startup and after startup (including a failed token refresh). The live transport
logs source changes with `third_party` and the host only, and retains each
endpoint's shared rate limiter. If every source fails, wallet synchronization
reports failure and readiness expires under the existing health policy. Neither
client sends an expired token after a refresh failure.

The loopback mock-server test is intentionally ignored in the socket-restricted
build environment. Run it on a host allowing sockets:

```sh
cargo test -p konsensus-chain bearer_mock_server -- --ignored
```
