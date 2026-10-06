# Move to a new node: close and send home

`konsensus move-home` migrates funds from a healthy embedded LDK node using its
**current, original live state**. It does not import SCBs or repair a lost disk.
Static channel backup restore is disabled, including preview: the pinned LDK
cannot safely start historical channel state. A stale commitment can lose the
whole channel. There is no override flag or production feature to unlock it.

## Before starting

Create a receiving address on the destination wallet/node, verify it there, and
keep its recovery material. The address must match the source Bitcoin network.
Stop the source's normal `konsensus` service and disable automatic restart while
migrating. Run the command as the node owner on its local console (an SSH session
with a controlling terminal also works). The existing state-generation lock
prevents concurrent normal startup or two maintenance processes.

This command has no HTTP endpoint. Pairing tokens, device keys and budget grants
cannot authorize it. It uses `/dev/tty` for explicit owner consent; piping `yes`
or passing an API token does not authorize a send. For an encrypted seed it
prompts for the password, or accepts the existing `--password-fd N` mechanism.
No new mnemonic is created or copied. Never point it at an old directory copy.

## Preview and begin

```sh
konsensus move-home --config /path/to/konsensus.toml \
  --destination ADDRESS_FROM_NEW_NODE --fee-rate 2
```

The default is preview. It starts and synchronizes the current live LDK node,
which can process existing protocol obligations; it does not request migration
closes or destination sweeps. The preview lists channels/peers, wallet balances,
anchor reserves, pending claims and unrelated local spend reservations, an approximate cooperative-close fee range
from LDK's current fee estimates, and the selected sweep rate in sat/vB.
The closing range assumes 200 vB per outbound channel and includes the configured
force-close avoidance allowance. It is an estimate, not a cap: peer negotiation,
actual transaction size and fee changes affect it. The reported Lightning value
is an estimate, excludes some commitment fees, and can change with HTLC outcomes.
Do not add pending sweep values to wallet values; they can overlap during sync.

```sh
konsensus move-home --config /path/to/konsensus.toml \
  --destination ADDRESS_FROM_NEW_NODE --fee-rate 2 --confirm
```

Type the exact `MOVE HOME ADDRESS` line on the controlling console. This records
the plan in `<mnemonic-parent>/ldk/move-home.json`, then requests cooperative
closure of all current channels. New inbound channels/payments are refused in
maintenance mode, and no app/API service or automatic liquidity client is started.
LDK can still fulfill existing channel/chain obligations.

The command reports pending closes, errors, HTLC resolutions, confirmation
requirements and CSV delays. A channel disappearing from the open-channel list
is **not** evidence its funds are available. It retains all wallet funds until
there are no open channels, Lightning claims, pending LDK sweeps or anchor
reserves. The journal also makes ordinary `konsensus start` refuse this store.

When funds are spendable, it previews the **exact** destination amount, mining
fee, and transaction ID. Type the separate `SEND … FEE … TO …` line to approve
that sweep. There is exactly one output, to the given address; no change output.
A changed wallet requires another preview. An address belonging to the source
wallet is rejected. The sweep rate is fixed in the plan (1–10000 sat/vB).

Fees for channel closes and LDK's intermediate claims are ordinary Bitcoin
mining fees; those intermediate claim outputs go to the source wallet before
its final drain. The only external migration recipient is your address.

## Unresponsive peers: explicit force-close

Prefer a cooperative close first. If a peer stays disconnected or stays connected
but stalls closing negotiation, stop the maintenance command with Ctrl-C and
resume with the same plan plus:

```sh
konsensus move-home --config /path/to/konsensus.toml \
  --destination ADDRESS_FROM_NEW_NODE --fee-rate 2 --confirm \
  --force-close USER_CHANNEL_ID --confirm-force-close
```

Use the `user_channel_id` shown as `id` in the channel preview; repeat
`--force-close` to name several channels. The command additionally requires the
exact `FORCE CLOSE …` line on the console. It refuses unknown channels. This
separate consent permits force-close regardless of connection state or whether
a cooperative request succeeded; disconnected peers cannot accept that request.
Successful cooperative requests are recorded, and channels already shutting
down are left to negotiate without repeated close requests or journal writes.
There is no automatic fee-negotiation timeout escalation. A narrow patch to the exact
pinned Lightning 0.2.2 enables this policy before every maintenance startup
(see `vendor/lightning/BITSOV-PATCH.md`). A connected but stalled peer remains
pending until it finishes negotiation or the owner explicitly authorizes force-close.

Force-close uses current live state and can cost more, require a CSV delay, and
leave HTLCs unresolved for much longer. Existing LDK protocol behavior can still
close a channel on peer/protocol failure; the flag controls owner-requested
force-closes, not Lightning protocol obligations.

## Restart, status and completion

Ctrl-C pauses the console job and stops LDK cleanly. Restart the same command
with the same config, destination and fee rate. Without `--confirm` it only
previews current state. With it, repeat the owner confirmation to continue;
previously recorded force authorization and sweep consent survive a restart.
Each new sweep still requires its own exact-amount confirmation.

Signed sweep bytes and consent are fsynced before any broadcast. On a crash or
unknown broadcast result, resume rebroadcasts **that same transaction**, never
a replacement send to a different address. Zero confirmations means locally
queued, mempool/unconfirmed, or unknown; it is not a claim of chain acceptance.
If a sweep input is missing or spent by a conflicting/replacement transaction,
replay stops with the sweep ID and an error instead of reporting zero confirmations
forever. Keep the journal and live store, synchronize the chain view, and investigate
the sweep and its input transactions. Resume only after resolving the cause; this
command does not automatically replace the approved sweep or clear its reservation.
Completion requires a successful chain sync, no remaining channels/claims/sweeps/
wallet balance, and at least six confirmations for every migration sweep.

If the backend is offline, fees exceed available funds/dust, a previous unrelated
local spend remains reserved, or journal persistence fails, the operation stops
with the error and retains its journal. Resolve the cause and resume. There is
no automatic RBF/fee increase, journal reset, destination change, or reservation
abandonment. Investigate unrelated reservations before beginning migration.
Do not delete or edit the journal to bypass a refusal. Keep the original live
store and seed after completion for reorgs or late payments; rerunning the same
plan can sweep newly arrived funds after a fresh amount/fee confirmation.
The source's normal service remains locked after completion. Use a fresh node
identity and receiving wallet for the new node.

Whitelist/relationship recovery remains a separate explicit command:
`konsensus whitelist restore --config … --from whitelist-latest.aes`.
SCB restore no longer auto-applies this sidecar.

## Tests

```sh
cargo test -p konsensus-lightning --test move_home --test scb_restore_locked
cargo test -p konsensus-node --bin konsensus move_home
cargo test -p konsensus-node --bin konsensus scb_restore
cargo test -p konsensus-lightning --test move_home_regtest --no-run
BITCOIND_EXE=/path/to/bitcoind cargo test -p konsensus-lightning \
  --test move_home_regtest -- --ignored --nocapture
```

The ignored regtest creates and advances a real channel, asserts the historical
restore entry point cannot write/start/broadcast, closes using current state,
restarts during cooperative negotiation and after durable sweep consent but before broadcast, and verifies the
single destination output and confirmed completion. It needs Bitcoin Core;
the default tests do not download or run it.
