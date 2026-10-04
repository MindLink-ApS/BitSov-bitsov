# BitSov Recovery

This document covers recovery for LDK static channel backups (SCBs) after L5a
and L5b.

**WARNING — issue #157 remains blocked on safe LDK recovery support. Do not run
`konsensus scb restore` against real funds, including without `--confirm`.** The
current command starts LDK with potentially revoked snapshot state even in its
so-called preview path. This documentation change does not disable that code.

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

These files are periodic snapshots of the full LDK channel manager, monitors,
and monitor updates, not a recovery-only static backup format. They can contain
revoked commitment state after the live channel advances. Even the newest local
backup does not prove that its commitments are safe to broadcast. Plain SCB files
must not be synced to third-party storage.

L5b uses AES-256-GCM with the node's master AES key derived from the mnemonic.
That means:

- the backup directory can be copied like ordinary files;
- the ciphertext is useless without the mnemonic and passphrase;
- a restored node with the same mnemonic can derive the same AES key and decrypt;
- there is no operator GCS dependency in the sovereign default.

## Restore From Local Rotated SCB

Automated recovery from these snapshots is currently unsafe. Preserve the
mnemonic, passphrase, and all backup files; keep snapshot state offline. Do not
start a normal LDK node on a restored snapshot or use `--confirm` to close its
channels. Contact counterparties to arrange closure from their latest state and
obtain reviewed recovery tooling before importing monitors to claim outputs.

Use only the newest available snapshot as a recovery input. If it is damaged,
obtain another copy of that same snapshot; do not substitute an older snapshot.
`scb-latest.aes` should match the newest timestamped copy. Timestamped copies are
retained for preservation and diagnosis, not permission to roll channel state
back. The current restore command does **not** enforce this rule.

## Issue 157 Recovery API Blocker

The investigation is against base `58ed59f`, vendored `ldk-node` 0.7.0, and the
`lightning` 0.2.2 version pinned in `Cargo.lock`. No runtime fix or new recovery
flags are implemented by this documentation change. Implementation stopped at
the requested API feasibility gate.

### Evidence in the current implementation

- `crates/konsensus-lightning/src/scb_restore.rs`,
  `decrypt_and_load_scb_backup`: imports the snapshot into SQLite, builds a
  normal LDK node, and calls `start()` before returning estimates.
- `crates/konsensus-node/src/cli/scb_restore.rs`, `cmd_scb_restore`: checks
  `--confirm` only after that startup. Absence of confirmation is not a
  no-broadcast guarantee. It calls `force_close_restored_channels` when confirmed.
- `vendor/ldk-node/src/lib.rs`, `close_channel_internal`: the public force-close
  method calls `ChannelManager::force_close_broadcasting_latest_txn`.
  `Node::start` starts chain synchronization and broadcast-queue processing.
  The pinned `lightning` 0.2.2 `ChannelManager` has no public
  `force_close_without_broadcasting_txn` method to expose through this wrapper;
  older-version examples of that API do not apply.
- `vendor/ldk-node/src/builder.rs`, `build_with_store_internal`: constructs its
  own transaction broadcaster, deserializes the manager with the saved monitors,
  and registers those monitors with `ChainMonitor`. There is no public recovery
  constructor or builder option for suppressing holder commitments throughout
  loading, startup, synchronization, reconnection, and restart.
- In the pinned `lightning` source, `src/ln/channel.rs`,
  `Channel::channel_reestablish` (around lines 9800–9835), receipt of a valid
  revocation secret proving we are behind deliberately **panics**. Its diagnostic
  directs operators to reconnect with an empty manager and no monitors, ensure
  peer closes have confirmed, then restart with an empty manager and the latest
  available monitors. Reconnecting a normal restored node is not that procedure.
- In `lightning` 0.2.2, `src/chain/channelmonitor.rs`, `ChannelMonitor` explicitly
  requires that active monitors not be out of date. `block_confirmed` calls
  `should_broadcast_holder_commitment_txn` for expiring HTLCs (around line 5644).
  Thus removing the explicit CLI force-close call does not establish safety.
  `broadcast_latest_holder_commitment_txn` documents the punishment risk of
  broadcasting after data loss (around line 2324).

The versioned upstream references are
[ChannelMonitor](https://docs.rs/lightning/0.2.2/lightning/chain/channelmonitor/struct.ChannelMonitor.html),
[ChannelManager](https://docs.rs/lightning/0.2.2/lightning/ln/channelmanager/struct.ChannelManager.html),
and [channel reestablishment source](https://docs.rs/lightning/0.2.2/src/lightning/ln/channel.rs.html).
The findings above were checked against the locally cached source for the locked
version, not against newer LDK documentation.

### Missing capabilities required for a safe implementation

1. A staged recovery interface that extracts channel identity and funding
   outpoints without activating snapshot monitors or a stale manager, reconnects
   using the same node identity with empty channel state, and requests or observes
   peer closure. Existing `Node::connect` is only a connection primitive; it does
   not perform this recovery protocol. Peer addresses must also be supplied or
   recovered: `scb_export.rs` exports manager and monitor namespaces, excluding
   the peer store and network graph.
2. Verified peer-close transactions and a safe monitor-only claiming phase.
   Recovery must confirm the funding spends before loading old monitors and
   safely handle chain catch-up, reorgs, restarts, claim construction, and sweeps.
   The current builder unconditionally uses a saved manager when present; merely
   deleting its row and starting old monitors does not supply these guarantees.
   A reviewed adapter or upstream support for LDK's staged procedure is needed.
3. A durable prohibition on broadcasting holder commitments from backup state,
   covering manager deserialization, monitor timers, chain updates, transaction
   rebroadcasts, and fee bumps while allowing valid recovery sweeps. The public
   vendored API has no such recovery policy. A general broadcast sink would also
   suppress sweeps; an ad hoc transaction filter is not a proven substitute.
4. Separate, persisted per-peer reachability evidence for the explicit last-resort
   operation, with a configurable minimum interval (default 14 days), reset on
   successful contact, checked across restarts, and a loud total-loss warning.
   Backup age or a single connection failure is not evidence of 14 days offline.
   Elapsed time never makes a revoked commitment safe. No automatic fallback is
   acceptable, including after the interval expires.
5. Backup freshness validation before any storage mutation or node startup.
   Compare the candidate with newer backups in the configured backup directory
   and its source directory; fail closed when ordering is ambiguous or the newest
   copy is damaged. The current encrypted payload has no authenticated snapshot
   generation/timestamp; filenames and filesystem modification times alone
   cannot prove ordering for renamed or copied files. A reviewed format and
   compatibility policy are needed for reliable freshness checks. Being newest
   on disk must never enable commitment broadcasting by default.

### Required regression coverage before enabling recovery

Use two funded regtest peers. Snapshot A, then complete a payment and revocation
exchange so A's saved holder commitment is revoked. Stop live A and invoke the
actual recovery entry point with the old snapshot and the original identity.
Record **every attempted broadcast**, not just transactions accepted into the
mempool. Assert that no saved holder commitment is submitted during import,
startup, chain catch-up, reconnect, waiting, restart, or sweep. Verify that B
closes with its latest state and A recovers its output. Include a pending-HTLC
snapshot and advance blocks through its timeout while B is offline to exercise
monitor-driven broadcasting. Exercise a reorg during recovery as well.

Test both default invocation and the legacy `--confirm` path. Verify that newer
local backups reject older inputs before storage changes, including renamed
copies, corrupt newest files, and conflicting ordering. Verify last-resort
requests fail before the configured interval, contact resets the interval,
restarts preserve it, and expiry alone never broadcasts. The regtest case can
use `konsensus-node`'s existing `regtest-e2e` feature. These tests have **not** been
implemented or run: a mock asserting that the CLI omitted a force-close call
would not demonstrate the required guarantee.

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

4. Use reviewed recovery tooling to identify and sweep channel outputs. The
   mnemonic alone does not make those outputs automatically discoverable by the
   ordinary on-chain wallet. Wait for required confirmations and timelocks before
   treating recovery as complete.

Counterparty closure and output recovery are separate steps. Periodic SCB
snapshots preserve useful recovery data but do not make normal node startup on
old channel state safe.

## Operator Checklist

- Keep the mnemonic offline.
- Keep `scb.bin` local only; sync only encrypted `.aes` files.
- Preserve the newest backup and its copies; never roll back channel state.
- Do not run the current SCB restore command on real channel backups, even in a
  separate directory. It can broadcast on the same network with the same keys.
- Validate future recovery tooling on regtest before trusting it with funds.
- If cloud sync is needed for Cloud-tier tenants, sync only L5b encrypted blobs.
