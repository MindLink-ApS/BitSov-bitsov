# BitSov Recovery

This document covers recovery for LDK static channel backups (SCBs) after L5a
and L5b.

## What Is Backed Up

L5a writes the current LDK static channel backup to:

```text
<data_dir>/scb.bin
```

L5b encrypts that file with the node identity's master AES key and rotates local
copies in:

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

For a lost/corrupt disk, retain the seed, passphrase, all backups and available
current state. Do not boot historical channel state or assume the mnemonic alone
recovers channel outputs. Coordinate with counterparties and obtain a recovery
procedure compatible with the pinned LDK; this release does not provide an
automated channel recovery guarantee. Counterparty closure alone does not prove
that this wallet can locate and spend every channel output.

Restore peer/invite relationships independently using
`konsensus whitelist restore --config … --from whitelist-latest.aes` after
verifying the sidecar's provenance. The SCB command no longer auto-applies it.

## Operator checklist

- Keep the mnemonic and passphrase offline and retain the current live state.
- Keep plaintext SCBs local; sync only encrypted `.aes` files.
- Preserve backup history for a future compatible recovery procedure, not rollback.
- Do not test channel restore by starting historical state against live peers.
- For moving a healthy node, preview and use `konsensus move-home` on the source.
