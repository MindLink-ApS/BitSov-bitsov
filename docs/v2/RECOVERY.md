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

SCB files contain channel metadata: counterparty pubkeys, funding outpoints,
channel identifiers, and balances/capacity hints. Plain SCB files must not be
synced to third-party storage.

L5b uses AES-256-GCM with the node's master AES key derived from the mnemonic.
That means:

- the backup directory can be copied like ordinary files;
- the ciphertext is useless without the mnemonic and passphrase;
- a restored node with the same mnemonic can derive the same AES key and decrypt;
- there is no operator GCS dependency in the sovereign default.

## Restore From Local Rotated SCB

Use this path when the node disk is lost or corrupted but the operator still has
an encrypted SCB copy.

1. Stop the node.

2. Restore the node identity from the mnemonic:

   ```sh
   konsensus restore --dir /var/lib/bitsov/node --tier full
   ```

   Use the same BIP-39 passphrase if the original node used one.

3. Choose the newest usable encrypted SCB:

   ```sh
   ls -1 /var/lib/bitsov/node/backups/scb-*.aes | tail -1
   ```

   `scb-latest.aes` should match the newest timestamped copy, but the timestamped
   copies are kept so an operator can step back if the latest file is damaged.

4. Run SCB restore in preview mode first:

   ```sh
   konsensus scb restore \
     --config /var/lib/bitsov/node/konsensus.toml \
     --from /var/lib/bitsov/node/backups/scb-latest.aes \
     --restore-dir /var/lib/bitsov/recovery/ldk-restore
   ```

   This decrypts the backup with the mnemonic-derived SCB AES key, imports
   persisted recovery state into a separate restore directory, and prints
   per-channel estimates:
   `channel_id`, `counterparty`, `estimated_recoverable_sats`.

5. Re-run with `--confirm` to execute destructive unilateral closes:

   ```sh
   konsensus scb restore \
     --config /var/lib/bitsov/node/konsensus.toml \
     --from /var/lib/bitsov/node/backups/scb-latest.aes \
     --restore-dir /var/lib/bitsov/recovery/ldk-restore \
     --confirm
   ```

   This initiates force-close for each recovered open channel.

6. Do not delete encrypted backup files until force-close transactions are
   broadcast and on-chain recovery balances are visible.

## Mnemonic-Only Recovery

Use this path when there is no SCB copy.

1. Restore the node identity from the mnemonic:

   ```sh
   konsensus restore --dir /var/lib/bitsov/node --tier full
   ```

2. Start with no channel state and do not attempt to reuse stale LDK data from a
   partial disk copy.

3. Coordinate with each channel counterparty to force-close or cooperatively
   close channels from their side. The restored node can derive its on-chain keys
   from the mnemonic, but it cannot reconstruct full channel state without SCB.

4. Wait for on-chain resolutions and CSV delays, then re-open channels.

Mnemonic-only recovery is slower and may require counterparty action. SCB
rotation exists to avoid this path.

## Operator Checklist

- Keep the mnemonic offline.
- Keep `scb.bin` local only; sync only encrypted `.aes` files.
- Prefer `scb-latest.aes` for restore; keep timestamped copies for rollback.
- Test restore on a non-production data directory before touching live funds.
- If cloud sync is needed for Cloud-tier tenants, sync only L5b encrypted blobs.
