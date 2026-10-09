# BitSov Recovery

This runbook covers lost-disk recovery with embedded LDK and `konsensus recover`
(#271). A healthy node moving home uses [move-home](../operations/move-home.md)
on its original live store instead.

## What Is Backed Up

L5a writes the current LDK static channel backup to:

```text
<data_dir>/scb.bin
```

L5b encrypts that file with a seed-derived SCB key and rotates local copies in:

```text
<data_dir>/backups/
```

The default retained files are:

```text
scb-latest.aes
scb-<timestamp>-<random>.aes
```

The default rotation count is 24 timestamped copies. At a 5 minute cadence this
keeps about 2 hours of local SCB history. Operators can change:

```toml
[backup]
scb_dir = "/path/to/backups"
rotation_count = 24
```

## Security Model

SCB files contain persisted LDK manager, monitor and update state, including
channel metadata and commitment history. Plain SCB files must not be
synced to third-party storage.

L5b uses AES-256-GCM with an SCB-specific key derived from the LDK entropy seed
(the mnemonic and optional BIP-39 passphrase).
That means:

- the backup directory can be copied like ordinary files;
- the ciphertext is useless without the mnemonic and passphrase;
- a restored node with the same mnemonic can derive the same AES key and decrypt;
- there is no operator GCS dependency in the sovereign default.

## SCB restore is locked (issue #157)

`konsensus scb restore` always fails closed, including preview and `--confirm`,
before reading the seed/backup, writing state, starting LDK or applying a
whitelist sidecar. Library import and restored force-close entry points are
also disabled. There is no override flag or normal-build feature.

These backups contain historical LDK channel-manager/monitor state. Starting a
stale copy can broadcast a revoked commitment and lose the entire channel. The
pinned LDK has no safe staged restore/broadcast-suppression path and can panic
when peer reconnection proves data loss. Merely reconnecting before requesting
a force-close is not a safe fix. Neither the newest snapshot nor any older copy
is proof of current channel state. Never roll back a live LDK store.

For a healthy node moving to new hardware, use the original current live store
and the owner-console [close and send home procedure](../operations/move-home.md).
It cooperatively closes channels, waits for claims, then sweeps to the address
you provide after fee/amount preview and consent. It is not disaster recovery.

## R1 — lost or wiped disk, original hub reachable

Use this only when the old node cannot run again. Keep its service disabled,
retain the mnemonic, original BIP-39 passphrase (if any), and encrypted backups.
If the original live disk is healthy, use move-home; restoring the same seed
alongside it can trigger closure of healthy channels. Losing only owner devices
while the box is healthy calls for console re-pairing, not seed restore.

### 1. Restore the seed into an empty directory

On the owner's terminal or SSH session with a controlling terminal, as the
account that will own the files:

```sh
konsensus restore --dir /absolute/path/recovered-node --tier full --encrypt
```

Enter the mnemonic at the prompt and a non-empty file-encryption password.
`restore` refuses a non-empty directory. Full tier writes an open
`ldk/recover.json` before the restored config becomes usable; normal `start`
remains fenced. Cloud/light identity-only restores do not create this embedded
LDK recovery journal. Do not copy an old LDK database into the new directory.

Before previewing, edit the generated `konsensus.toml` for the **original Bitcoin
network**, chain backend and original hubs. The full-tier defaults are not a
reconstruction of the lost config. `restore` has no BIP-39 passphrase argument:
if the original seed used one, set `[identity] passphrase` to that same value
before recovery. This is distinct from the mnemonic-file encryption password.
Protect the config file accordingly.

Recovery requires embedded LDK and a configured bitcoind, Electrum or Esplora
chain source; mock and external Lightning backends are not supported. Configure
all original peers in `lightning.liquidity.providers`, with their public keys
and addresses, and set `lightning.liquidity.enabled = true` plus
`selected_provider` to the LSPS2 hub used for the final test. A supplied backup's
active counterparties must all be configured hubs. The command uses those
configured sources; it does not discover a replacement hub.

### 2. Preview offline

```sh
konsensus recover --config /absolute/path/recovered-node/konsensus.toml
# Optional: narrow the scan with an encrypted backup retained outside the new store.
konsensus recover --config /absolute/path/recovered-node/konsensus.toml --backup /secure/scb-latest.aes
```

Without `--confirm`, the command derives the identity, destination and recovery
scripts without constructing LDK or querying the chain. It still checks the
recovery directory, takes the process lease and verifies/establishes the host
binding. An encrypted seed prompts for its password; `--password-fd N` can
supply that password, never recovery consent.

The backup is decrypted and parsed **in memory as an index only**. Its active
funding outpoints, peers and v2 static scripts narrow the search; historical
balances are not current balances. No backup manager or monitor is imported
into LDK. A stale index can omit later channels. Unsupported formats, wrong
keys and non-v2 scripts fail closed; this command does not implement legacy
random-key channel recovery.

Without a backup, the command scans 2,000 seed-derived v2 scripts (anchor and
non-anchor). Esplora can require at least one HTTP request per script per scan,
reveals those scripts to the configured service, and is subject to its rate
limits. Finding nothing does **not** mean recovery is complete. Seed-only
recovery cannot prove that all old channels have closed; retain the seed for
late closes even after a completed run.

The default sweep destination is this seed's own on-chain wallet. Use
`--destination <address>` for an explicit address on the same network.
`--fee-rate <sat/vB>` defaults to 2 and accepts 1–10000. Keep the same
node/network/destination/fee/backup plan when resuming.

### 3. Confirm hub closure and each sweep

Repeat the chosen preview command, with the same options, adding `--confirm`.
Read the warnings and type the exact console challenges:

- `OLD NODE IS GONE`
- `RECOVER FROM HUB CLOSE`

Consent comes from `/dev/tty`, not stdin, an HTTP endpoint, a paired app or a
password descriptor. The close/sweep phase creates a fresh private LDK session
with no old manager or monitors. API listeners, liquidity and inbound channel
acceptance are disabled. Reconnection lets the hub close using **its** channel
state. Recovery never uses a backup to broadcast a funding spend.

The command scans for confirmed, spendable outputs and validates their closing
transactions; with an index it also checks known funding spends. Anchor outputs
require their one-block CSV delay. For each proposed sweep it displays the txid,
net amount, fee and single destination output. Type the exact displayed
`SEND <amount> FEE <fee> TO <destination>` only after checking it.
The approved transaction is journaled before broadcast. Recovery waits for six
sweep confirmations and, with an index, six confirmations of all indexed
funding spends. It rechecks receipts across restarts and before completion;
missing or reorged receipts leave recovery open.

The hub is trusted to publish its latest state. There is no recovered monitor
or watchtower protection against a dishonest hub publishing a revoked state.
In-flight HTLCs may be lost; the command does not recover every possible channel
claim or guarantee the historical backup balance.

### 4. Verify a fresh channel before normal startup

After sweeping, the command checks identity, chain readiness and (for the
default destination) the recovered on-chain wallet balance. It then creates a
new canonical LDK store for Lightning verification, keeping normal startup
fenced. **Keep this new live store**, including `RECOVERY_STORE` and the journal,
across interruptions; never replace it with a snapshot.

The selected LSPS2 hub must offer a fresh channel. The command previews a
funding quote and asks for `SELF TEST FUND … FEE … HUB …` before displaying an
invoice. Pay that invoice **from another wallet**; it does not spend recovered
on-chain funds for this step. Defaults are `--self-test-funding-sats 20000` and
`--self-test-max-fee-sats 2000`; the actual quote still needs console approval.
The hub may defer opening until the old close resolves. Follow the console's
expired-invoice guidance before replacing or paying another invoice: an earlier
in-flight payment can still settle.

Once funded, the fresh channel must be usable and `money_ready` true. Confirm
`SELF TEST SEND 1 SAT TO …`; completion requires that direct hub payment to
settle. Failed payments require explicit retry consent. Only after verification
and the final chain recheck does the command write `state: "done"` and print a
`Recovered` report with closing/sweep txids, recovered sats and the self-test
result. A valid completed journal allows:

```sh
konsensus start --config /absolute/path/recovered-node/konsensus.toml
```

Check current owner status, balances and channels after startup; the completion
report records checks at recovery time, not a perpetual readiness guarantee.

### Pause and resume

Ctrl-C pauses the polling/verification loops, retaining the journal and approved
transactions. A failure also leaves recovery fenced. Resume `konsensus recover`
with the same config and plan, including the same backup selection and explicit
destination if used, then `--confirm`. It rechecks and may rebroadcast the
**same approved sweep**; do not delete journals to obtain a new plan or bypass
startup. During verification, retain the newly created live store.

## R2 — hub unreachable or unwilling to close

The command may fail with `waiting for hub; recovery remains open`, or wait for
confirmed close outputs. No outputs is not success. Keep the journal, seed and
backups, contact the hub operator with the original node identity, and arrange
closure from the hub's side. Resume the same command when connectivity and the
hub close are available. Completion also needs the selected LSPS2 hub and an
external wallet for the fresh-channel verification above.

There is no backup-based force-close fallback, timeout override or automatic
completion for an empty scan. If the hub never closes, seed-only recovery cannot
sign its funding spend and those funds can remain locked. Do not start an old
snapshot, downgrade, or use `rebind-instance` to bypass this limit.

## Read-only owner status

When the normal API is running, owner `GET /api/v1/status` reports
`recovery.state` for the configured embedded-LDK journal:

| State | Meaning |
|---|---|
| `absent` | No recovery journal at the configured location; not proof of recovery. |
| `open` | Recovery remains in progress; resume on the owner console. |
| `done` | Journal permits normal startup (the command records its completed verification). |
| `unavailable` | Journal could not be read/validated; not success. Inspect it locally. |

The field is omitted when no embedded recovery location is configured. It
contains only the state, with no seed, invoice, transaction body, path or raw
error. Public health and non-owner routes do not expose it, and status cannot
start, confirm, resume or complete recovery. An app can render `open` as
“Recovery in progress” and `done` as “Recovered”; no app-driven recovery is
provided here. `recover` itself serves no HTTP API, and an open/invalid journal
blocks normal start, so use console output while recovery is running rather
than expecting live app progress.

## Relationships and retained records

Restore peer/invite relationships independently using
`konsensus whitelist restore --config … --from whitelist-latest.aes` after
verifying the sidecar's provenance. The SCB command no longer auto-applies it.

## Operator checklist

- Keep the mnemonic and passphrase offline and retain the current live state.
- Keep plaintext SCBs local; sync only encrypted `.aes` files.
- Preserve encrypted backup history as a recovery index, never as a live store.
- Do not test channel restore by starting historical state against live peers.
- For moving a healthy node, preview and use `konsensus move-home` on the source.
- For lost disks, follow R1/R2; retain the recovery journal and completion report.
- Never remove safety markers or boot two nodes with the same identity.
