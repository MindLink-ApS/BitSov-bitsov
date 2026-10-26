# Run your own BitSov node on signet

This is the developer path from a fresh checkout to a paid message between two
nodes you control, on Bitcoin **signet**. About 15 minutes of typing; signet
block times add waiting where a confirmation is needed, and those waits are
marked.

**What this is and is not.** BitSov is in closed beta on signet test nodes.
Paid admission follows the [2026-07-01 keystone](v2/F1-CAPPED-FIRST-CONTACT.md)
(the target re-prices and the requester pays its invoice), and **mainnet is not
supported for the public beta**: this guide never uses it and nothing here
funds a mainnet wallet. Signet coins have no value. There is no final signed
release yet (only pre-release candidates); this guide builds from source. Every
step below was run as written in the session that produced this guide unless it
is marked **untested in CI**;
the [appendix](#appendix-what-was-tested) says exactly what ran where.

You need two nodes to exchange a paid message: yours and a contact's. "Contact"
below can be a second machine of your own or a second person following the
same steps. The nodes must reach each other's IP address and ports (same LAN, a
tailnet, or two VPS hosts; see [reachability](operations/reachability.md)).
Both nodes need some signet sats from a faucet (amounts in step 5).

Doctrine, so the steps make sense: **payment is the connection**, so there is
no free first message, even to a contact you listed. **Keys are identity**: your
node ID is derived from the recovery phrase `init` writes, and Bitcoin anchors
energy and admission, never identity.

## 1. Build from source

Rust, installed through rustup, is the only build dependency. The checkout
pins the exact compiler in `rust-toolchain.toml` (**1.99.1** today, with
clippy and rustfmt); rustup installs it on first use inside the checkout, and
CI builds on the same version. See [the toolchain pin](ci/RUST-TOOLCHAIN.md)
for how that relates to the minimum supported version (`rust-version` 1.89 in
`Cargo.toml`) and to the release-binary toolchain (**1.91.1** in
`scripts/release-toolchain`; use `cargo +1.91.1` only to reproduce a release
build). This guide was run on stable 1.97.0 before the pin landed.

```sh
git clone https://github.com/MindLink-ApS/BitSov-bitsov.git
cd BitSov-bitsov
rustc --version   # rustup installs the pinned toolchain the first time
cargo build --release -p konsensus-node
./target/release/konsensus --version
```

The binary is `target/release/konsensus`. The first build compiles the vendored
LDK stack and takes a while (tens of minutes on four cores). The rest of this
guide assumes it is on your `PATH`:

```sh
export PATH="$PWD/target/release:$PATH"
```

## 2. Initialize a node on signet

`init` creates a data directory, a 24-word recovery phrase, and
`konsensus.toml`. Use the `full` tier: it is the one with embedded Lightning
(LDK) and a real chain source, which signet needs. Pick a dedicated directory
owned by you: `init` creates it, or re-uses an empty one, at mode `0700`, and
writes the recovery phrase owner-only (`0600`). At startup the node chmods a
group- or world-readable `mnemonic.txt` back to `0600` and refuses to start if
that fails.

```sh
konsensus init --dir ~/bitsov-signet --tier full
```

It shows the recovery phrase and asks you to confirm three words. **Write the
phrase down.** It is the only way to recover the identity and the LDK wallet.
The phrase is stored in `~/bitsov-signet/mnemonic.txt` in plain text; to
encrypt it at rest instead, add `--encrypt` and type a password when asked
(then `start` prompts for it, or read [password input](operations/password-input.md)
for launchers).

`init` writes a **mainnet** Lightning network and mainnet chain URLs into a fresh
config today. Switch them to signet before the first start. Open
`~/bitsov-signet/konsensus.toml` and change these keys in place, leaving
everything else as written (do not paste a second `[lightning]` or `[chain]`
table; TOML rejects duplicates):

```toml
[lightning]
backend = "ldk"
network = "signet"
esplora_url = "https://mempool.space/signet/api"
esplora_url_fallback = "https://blockstream.info/signet/api"
hub_only_channels = false

[chain]
backend = "esplora"
api_url = "https://mempool.space/signet"
esplora_url_fallback = "https://blockstream.info/signet"
```

The URLs are the signet endpoints of the same two public Esplora operators
`init` already wrote; any Esplora-compatible signet server works, including
your own Bitcoin Core or Electrum server (see [chain source](CHAIN-SOURCE.md)).
A public Esplora can link the addresses your wallet watches to your IP; that is
the trade-off of not running your own chain source.

`hub_only_channels = false` is new in this file. By default an embedded LDK
node opens channels only to a configured hub or LSP, because nothing watches a
home node's channels while it is offline yet, and a fresh config has no hub.
Step 7 opens a channel straight to your contact, which needs this opt-out. It
applies to a plain start like step 3; a lockable start (`--home`,
`--remote-unlock`) stays hub-only regardless. Keep the node running while the
channel is open.

Defaults you are keeping, so you know what will listen:

| Setting | Default | Used for |
| --- | --- | --- |
| `[api] listen_addr` | `127.0.0.1:3141` | Owner HTTP API, loopback only |
| `[network] listen_addr` | `0.0.0.0:9736` | BitSov peer protocol (contacts dial this) |
| `[lightning] listening_address` | `0.0.0.0:9735` | LDK peer port (channel opens dial this) |
| `admission_mode` | `whitelist` | Only listed contacts may connect |

Open 9735 and 9736 (TCP) to your contact. Keep 3141 on loopback.

## 3. Start the node

```sh
konsensus start --config ~/bitsov-signet/konsensus.toml --owner-control
```

`--owner-control` creates `~/bitsov-signet/control.sock`, the owner console
the `peer add` command in step 6 talks to. It is off by default on purpose; see
`konsensus start --help`. Leave this terminal running and open a second one
for the rest.

The log prints your node ID (`node built node_id=…`). You can also read it
without the node running:

```sh
konsensus node-id --config ~/bitsov-signet/konsensus.toml
```

Startup on signet first syncs the LDK wallets against the Esplora server. Until
both wallets have synced, money routes answer HTTP 503 `not_ready` and status
reports `money_ready: false`. Wait for `money_ready: true` before step 5.

## 4. Pair your terminal with the node (owner token)

The HTTP API is loopback only and every owner route needs a bearer token. The
owner's token comes from signing a challenge with the node's own key, which is
what `docs/ops/owner-token.sh` does with `konsensus sign-challenge`. Source it
(do not execute it), with `curl` installed:

```sh
cd BitSov-bitsov
KONSENSUS_CONFIG=~/bitsov-signet/konsensus.toml source docs/ops/owner-token.sh
```

It sets `OWNER_TOKEN` in your shell for 24 hours and never writes it to disk.
A token minted this way carries every scope (read, receive, spend, admin, …):
it is the owner's key, not a paired app, so it is not metered by a budget
grant. The commands below use:

```sh
API=http://127.0.0.1:3141/api/v1
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" $API/status | jq .
```

Fields to watch in `status`: `node_id`, `money_ready`, `block_height`,
`lightning_backend` (`ldk`), `lightning_node_pubkey` (your contact needs this
in step 7) and `chain_view` (`backend: esplora`, `trust_level: third_party`
with the public servers above).

## 5. Fund it from a signet faucet

Ask the node for an on-chain address once `money_ready` is `true`:

```sh
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" $API/payments/funding-address | jq .
```

The response includes `"network": "signet"`; if it says anything else, stop
and fix step 2. Paste the address into any public signet faucet (search for
"bitcoin signet faucet"; MindLink does not run one). Request at least
**150,000 sats** on the node that will open the channel (the 100,000-sat
channel below, its funding fee and the local reserve) and at least
**30,000 sats** on the node that will accept it: every channel keeps a local
anchor reserve (default 25,000 sats) on each side, and an unfunded node refuses
an inbound channel. **Wait for one confirmation** (signet blocks are roughly
ten minutes apart) and check:

```sh
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" $API/payments/balance | jq .
```

`balance_msat` includes spendable on-chain funds; on LDK the response also
breaks the wallet down per category.

## 6. Add a contact

Exchange two things with your contact out of band: the 64-hex **node ID** and
the **IP address and peer port** (`<ip>:9736`). Node IDs are the identity;
the address is only a reachability hint, and hostnames are not accepted here.
Then each of you lists the other on the owner console:

```sh
konsensus peer add --config ~/bitsov-signet/konsensus.toml \
  --node-id <their 64-hex node id> --addr <their ip>:9736 --label "Alice"
```

It prints the fingerprint and address, waits for Enter (add `--yes` in
scripts), then persists the contact, whitelists it and dials it. The reply says
`connected` or `not reachable yet` with the reason; the node keeps retrying,
and the contact survives restart without a config edit. Because the default
admission mode is `whitelist`, a node that has not listed you refuses your
connection: whoever runs this first sees
`not reachable yet (… not in whitelist)` until the other side has run it too.
Check from either side; the answer is the list of connected node IDs:

```sh
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" $API/peers/connected | jq .
```

## 7. Open a channel to the contact

A paid message needs a Lightning route. Two fresh signet nodes have none, so
one of you opens a private channel directly to the other. The opener needs the
contact's `lightning_node_pubkey` (from their `status`) and their LDK address
(`<ip>:9735`). Preview first with `dry_run`, then open:

```sh
curl -sS -X POST -H "Authorization: Bearer $OWNER_TOKEN" -H 'content-type: application/json' \
  $API/payments/open-channel -d '{
    "peer_pubkey": "<their lightning_node_pubkey>",
    "peer_addr": "<their ip>:9735",
    "amount_sats": 100000,
    "push_sats": 10000,
    "funding_priority": "fast",
    "max_funding_fee_sats": 2000,
    "dry_run": true
  }' | jq .
```

Drop `"dry_run": true` to broadcast. `push_sats` gives the contact a balance so
they can pay you back; it is their money once the channel is open. The channel
is private (`announce` defaults to false). The default per-channel cap is
1,000,000 sats.

**Wait for the channel to become usable** (the acceptor's required funding
depth, usually six signet blocks, so around an hour; no deadline is promised):

```sh
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" $API/payments/channels | jq .
```

Both ends must show the channel ready. [Funding fees](ops/funding-fees.md)
explains `funding_priority`, and [all-in fee caps](v2/ALL-IN-FEE-CAPS.md) the
routing-fee policy used below.

## 8. Send a paid message

```sh
curl -sS -X POST -H "Authorization: Bearer $OWNER_TOKEN" -H 'content-type: application/json' \
  $API/messages/compose -d '{
    "recipient": "<their 64-hex node id>",
    "kind": 0,
    "plaintext": "hello from signet",
    "max_total_msat": 20000
  }' | jq .
```

`kind: 0` is a chat message. The node encrypts it end to end (X3DH and the
Double Ratchet), pays the recipient's chat price over the channel, and sends
it. The default chat price is 10 msat, which the node raises to its
1,000 msat invoice minimum; `max_total_msat` caps principal plus routing fee (6,000 msat
is the smallest cap that fits under the default fee policy; 20,000 leaves room).
A listed contact pays the message price only; a stranger would pay admission
as well, which is the first-contact path described in
[capped first contact](v2/F1-CAPPED-FIRST-CONTACT.md).

A successful response has `"state": "acked"`, `"accepted": true`,
`"delivered": true`, `"amount_msat": 1000` and a `payment_hash`. On the
contact's node, with their own owner token:

```sh
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" "$API/messages?peer=<your node id>" | jq .
```

lists the message with its decrypted `plaintext`, and their `payments/balance`
has gone up by the price. That is the whole loop: identity from keys, admission
by payment, content end to end encrypted.

## Stopping, restarting, troubleshooting

- **Stop** with Ctrl-C in the node terminal; LDK state and the SQLite store are
  in the data directory. Restart with the same `start` command. Do not re-run
  `init` on a directory that has one (it refuses) and never run two processes
  on one data directory.
- **503 `not_ready`** on money routes: wallets are still syncing, or the
  Esplora server is unreachable. `status` shows `chain_sync` when a sync has
  failed.
- **`peer add` says the node must be running with `--owner-control`**: start
  it with that flag (step 3).
- **`open-channel` refused with `not_dispatched`**: the reason is in the body,
  for example not enough confirmed on-chain funds or a fee cap below the
  estimate. If the other side refused it, they have no reserve yet: fund the
  acceptor too.
- **Compose fails with 503 `peer_not_ready`** and the recipient's log shows
  `not in whitelist`: the recipient has not listed you, so their node refuses
  your connection. They run step 6.
- **`open-channel` refused with `HUB_ONLY_WHILE_LOCKABLE`**: the
  `hub_only_channels = false` line from step 2 is missing, or the node was
  started lockable.
- **Running as a service** on a home box, with an encrypted seed and remote
  unlock, is a different setup: [home node](operations/home-node.md).
- **Upgrading** a retained node later: [UPGRADING](UPGRADING.md).

## Appendix: what was tested

Every command above was run in the session that wrote this guide, against a
`konsensus` binary built from this tree with stable Rust 1.97.0, except where
marked **untested in CI**. The session had no outbound access to signet Esplora
servers and no Bitcoin Core, so the steps that need a chain were exercised on
two local nodes on one machine with the node's mock Lightning backend
(`shared_mock`, a local settlement ledger with no real funds), and the
signet-specific steps are marked.

| Step | Ran as written | Notes |
| --- | --- | --- |
| 1. Build | yes | `cargo build -p konsensus-node` on stable 1.97.0, before `rust-toolchain.toml` (1.99.1) landed on main; neither pinned version was installed in the session |
| 2. `init --tier full`, config edit | yes | Fresh config confirmed to contain `network = "bitcoin"` and mainnet URLs; after the edit the node starts, logs `network=signet`, and reports `money_ready: false` because the Esplora servers were unreachable from the session |
| 3. `start --owner-control` | yes | Signet config above, and two mock nodes on loopback ports |
| 4. Owner token, `status` | yes | `docs/ops/owner-token.sh` on both nodes |
| 5. Faucet, `funding-address`, one confirmation | **untested in CI** | Needs a reachable signet Esplora and a faucet; the route and its `network` field were read from source, and on a mock node it answers 400 as expected |
| 6. `peer add` both ways, `peers/connected` | yes | First side reports `not reachable yet (… not in whitelist)` until the second side lists it; the contact survived a restart of the node |
| 7. `open-channel`, `payments/channels` | **untested in CI** | Needs signet funds; request shape, the hub-only default and refusal codes were read from source and [funding fees](ops/funding-fees.md) |
| 8. `compose`, recipient `messages?peer=`, reply | yes | `state: acked`, `accepted` and `delivered` true, `amount_msat: 1000`; sender balance down 1,000 msat, recipient up 1,000 msat; plaintext readable on the recipient; the reply paid the same way |

No mainnet instruction appears in this guide and `allow_mainnet` is not touched.
