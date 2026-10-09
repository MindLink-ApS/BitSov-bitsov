# Owner-console recovery after disk loss

`konsensus recover` is for a lost or wiped node. If its current live disk still
works, use `move-home`. Keep the old node disabled throughout recovery.

1. Run `konsensus restore --dir NEW_DIRECTORY --tier full` and enter the recovery
   words. The directory must be empty. Restore writes an open `ldk/recover.json`
   before writing the identity/config; normal startup is fenced.
2. Set the original Bitcoin network, chain source, and hub(s) in the new config.
   Enable `lightning.liquidity` and select the hub for the final LSPS2 test.
3. Preview with `konsensus recover --config NEW_DIRECTORY/konsensus.toml`.
   Optionally add `--backup /path/to/scb-latest.aes`. This reads an encrypted SCB
   as a metadata index only; a copied live directory is never a recovery store.
   A stale index can omit channels opened after that snapshot. Omit `--backup`
   to scan all 2,000 scripts when the channel inventory is uncertain.
4. Add `--confirm` and type `OLD NODE IS GONE`, then `RECOVER FROM HUB CLOSE` on
   `/dev/tty`. Recovery starts an empty LDK session and connects to the hub(s).
   The hub must publish its latest commitment. No backup manager, monitor,
   monitor update, or historical commitment is loaded into this session.
5. Review each exact sweep txid, amount, fee and destination. Type the displayed
   `SEND … FEE … TO …` challenge. The default destination is the restored seed's
   first BIP84 wallet address; `--destination` selects another address on the same
   network. `--fee-rate` is sat/vB. The exact signed sweep is durably saved before
   broadcasting. Inputs must be confirmed, still unspent, and mature for CSV-1.
6. Wait for six confirmations. Identity, chain readiness and the recovered
   on-chain wallet balance are checked. Normal start remains fenced.
7. The separate verification phase creates the **canonical new live store**,
   enables only the selected LSPS2 hub, and presents a fresh-channel funding
   invoice. Pay it from another wallet. The default gross amount is 20,000 sats,
   with a 2,000-sat fee cap; use `--self-test-funding-sats` and
   `--self-test-max-fee-sats` to change these bounds. The exact quote needs typed
   consent. These funds are not taken from the on-chain sweep. After it settles,
   separately authorize the 1-sat hub test (zero routing-fee budget). Only a
   successful payment and a fresh six-confirmation recheck close the journal.
   The hub may refuse fresh liquidity until its old closing monitor is archived
   and its own sweep completes. Keep the journal open and resume later; this
   command never bypasses the hub's capital limits. An unpaid invoice can be
   replaced after expiry with fresh typed consent. Confirm failure in the paying
   wallet first: an in-flight payment can settle after expiry. Earlier invoices
   remain tracked, including after a restart.
8. Run normal `konsensus start` with the same config. It retains the newly created
   Lightning channel. The journal records closing/sweep txids and the self-test.

Interruption or any error retains the journal. Resume the same command with the
same seed, network, destination, fee rate and backup. Once verification begins,
retain that **new live store**, including `RECOVERY_STORE`; do not replace it with
a snapshot. Failed self-test payments require typed retry consent. No API token,
paired device, piped input or `--yes` flag can authorize recovery.

Core uses `scantxoutset` plus mempool-aware `gettxout`; Electrum batches script
queries; Esplora uses the configured endpoints and authentication. A seed-only
scan uses all 2,000 v2 scripts and can be expensive on Esplora. A changing chain
view or an unavailable/pruned historical transaction leaves the journal open.
Core without txindex can inspect the last 288 retained blocks for a close/sweep;
older transaction evidence requires an indexed/archive source. A zero-balance
indexed channel is resolved only from an authenticated, six-confirmation funding
spend, never from the absence of a recoverable output. Authenticated closing
transaction IDs are journaled and rechecked on resume, including long pauses.

Recovery relies on an honest reachable hub. In-flight HTLCs and legacy v1 payment
keys are not recovered. No-backup scanning cannot prove how many old channels
exist; retain the seed for late closes. The host-binding fence detects restored
copies on another host or volume; it does not prove freshness of a same-host disk
image rollback. Never start a historical copied directory.

## Local regression drill

No binaries are downloaded by the test:

```sh
cargo build -p konsensus-node
BITCOIND_EXE=/path/to/bitcoind cargo test -p konsensus-lightning \
  --test recover_regtest -- --ignored --nocapture
```

`KONSENSUS_EXE` can select a different freshly built CLI. The test advances H/B
state after a snapshot, wipes B, runs both backup-index and seed-only recovery,
records every recovering-B broadcast, checks the exact latest H commitment and
balance minus fees, invokes normal CLI startup against a changed-host snapshot,
and tests a new LSPS2 channel and 1-sat return payment with an external payer.
The fixture supplies a deterministic 2 sat/vB fee estimate because an empty
regtest chain has no estimator history; all chain data and transactions use
bitcoind. It mines the hub's real monitor archival delay before requesting fresh
liquidity, so the complete drill takes several minutes.
