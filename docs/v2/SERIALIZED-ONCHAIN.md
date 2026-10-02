# Serialized on-chain operations (#189)

Atlas run 2 items 10 and 12 exposed a funding double spend: returning from
`Node::open_channel` only means negotiation started. Neither BDK transaction
construction nor LDK's asynchronous broadcast queue reserves wallet inputs.

## Operation boundary

Each LDK node now owns one async operation mutex. Opens, sends, closes, and
asynchronous close/HTLC fee-bump workers share it. Owner operations transfer the
lock to a worker once dispatched, so disconnecting the HTTP caller cannot release
it early. Funding events complete the operation already holding the lock.
Bump events enqueue a runtime-tracked worker instead of waiting on the event
processor; waiting there could block funding events needed by the lock holder.
LDK regenerates unresolved bump events on restart.

An open waits up to 60 seconds for the funding outpoint, then up to 10 seconds for
the configured Bitcoin Core, Electrum, or Esplora source to report the transaction.
It returns the same channel ID on success. The detailed API returns `opening`
when the funding tx is visible, or successful `pending_visibility` with the
channel ID and funding txid after the visibility window. Lookup errors are retried
through the whole window and do not imply broadcast rejection. A reservation
persistence failure after a positive sighting is logged without misreporting the
open as failed. Missing funding still reports an uncertain handshake outcome;
no automatic force-close or retry is added. Cooperative close waits for LDK to remove the
channel, with a 60-second bound; a timeout reports uncertainty.

## Wallet invariant

Before exposing a signed transaction, the wallet writes its local spend record,
uses BDK 2.3's `apply_unconfirmed_txs`, and persists BDK under the wallet lock.
Builders use BDK's `unspendable` input filter against the durable local records.
This separate record matters: Core sync can evict a locally prepared transaction
that is not yet in its mempool; eviction must not release its reserved inputs.
Unverified change is also excluded until source visibility or confirmation.

Records live in the node's existing KV store under `bitsov_local_spends`, keyed by
txid. Version 2 records creation and last-source-sighting Unix times; legacy rows
receive a durable migration timestamp once. Malformed/unreadable rows are skipped
with a warning and counted at `/api/v1/status` under `local_spends.unreadable_rows`;
active reservation txids and timestamps are listed there too. A failure to list
the namespace or persist a migration remains a storage error.

Definitive LDK funding rejection or `DiscardFunding` evicts the prepared parent
and releases its inputs. A pre-broadcast persistence failure runs abandonment
before returning, including KV cleanup even if BDK persistence is still broken.
Confirmation removes the reservation; a confirmed conflicting replacement also
releases the superseded transaction's unused inputs. Both transaction-based sync
and Core's block listener update this state.

The adapter queries the configured chain source at startup and every minute.
Each pass has a total 10-second budget, releases the gate between reservations,
and resumes after the last attempted txid so a stalled row cannot starve others.
Successful absence releases a reservation only after 24 hours since creation or
the last successful sighting, whichever is later. A recent eviction, lookup
failure, or verification timeout alone cannot unlock coins. BDK eviction is
persisted before ordinary release so abandoned change cannot be selected after
restart. Eviction persistence failure retains the reservation for owner/reconcile
retry; pre-broadcast construction rollback is the exception because no signed
transaction escaped. Source errors retain the record for a subsequent retry.

`POST /api/v1/payments/release-local-spend` accepts `{ "txid": "<64 hex>" }` and
requires the owner's spend token. The existing `ScopedAuth<Spend>` extractor
rejects pairing-bound tokens, including budget grants. Recovery is available
without `money_ready`; it serializes with opens/sends/bumps. Release is specific
and idempotent. Its response warns that the signed transaction may still propagate;
the owner must inspect channel/transaction state before spending released inputs.
Bounded absence likewise does not prove a transaction can never return.

Close fee bumps still use LDK's selector and fee/weight calculations. Its candidate
view prefers free inputs and inputs belonging to the same persisted claim,
including after restart. LDK's documented last-resort bump-versus-bump conflict
fallback remains available; ordinary send/funding reservations are never candidates
for it. Signing rechecks these exclusions. Amounts, fee settings, and admission
rules are unchanged.

## Offline verification

Regression tests exercise real BDK signing and persistence with disposable,
unstarted nodes: concurrent funding, send/funding ordering, eviction and restart,
unverified change, definitive abandonment, close fee inputs, stale selection,
claim-specific selection after restart, RBF fallback, direct Core confirmation,
and confirmed replacement cleanup. Async tests cover cancellation-safe gating,
node independence, bounded funding failure, retried lookup errors, pending
visibility success, and the unchanged channel ID. HTTP tests cover the successful
pending response, owner release, pairing refusal, and status diagnostics.

HTTP-fixture and live-node suites require sockets and are excluded from this job's
no-network run. Standalone vendored clippy has pre-existing failures (254 on the
untouched base); this job does not suppress or bulk-edit upstream lints. See the
commit message for the final verification results.

Doctrine: 1, 5, and 6 hold: settlement/admission is unchanged, locally held funds
remain under the node's keys, and an unverified funding transaction is reported as
uncertain. Lines 2–4 are unchanged; no identity registry, directory, or central
service is introduced.
