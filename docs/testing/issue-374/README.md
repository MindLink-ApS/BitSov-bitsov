# Issue #374: deterministic timing and isolation fixtures

Scope: the eight entries in issue #374 and its 22 October 2026 comment. The reconnect entry expands to 21 tests. All fixture wallets are mock/regtest; the offline fee test uses a private loopback HTTP 503 server.

## Causes and changes

| Test | Timing/isolation dependency removed |
| --- | --- |
| `sponsor_tests::regression_signed_request_expiry_is_enforced_at_approval` | Signed deadline was wall time + 2 seconds; candidate creation could already be late. A per-pair clock now holds time during setup and advances exactly to expiry. Assert refusal, no payment, and refusal after clock rollback. |
| `sponsor_tests::expired_candidate_resubmission_persists_terminal_expiry_even_on_refusal` | Same two-second candidate race and three-second sleep. Advance the pair clock exactly to expiry and inspect the persisted terminal state and time floor. |
| `sponsor_tests::reconciliation_cannot_release_a_live_dispatch_from_an_older_failed_record` | Five-second spin deadline included queued ledger/fsync work behind the process-wide sponsor lock. Await the mock's dispatch-entry notification, or fail on premature request completion. Distinct per-test ledger paths were already present. |
| `budget_grant::sponsor::cancelled_owner_dispatch_retains_its_purse_reservation_for_restart` | Same five-second dispatch-entry deadline. Await entry before cancellation; retain the durable purse-reservation and restart assertions. Its sponsor/newcomer share a fixed per-kit clock; its existing temporary directory owns its journals. |
| `session_handler::budgeted_reconnect_two_node::*` | Quarantine epoch was created inside a spawned recipient task, but setup slept independently for 1.1 seconds. A late task start restarted the quarantine after that sleep. Initialize an already-running gate explicitly in test-only code. Connection-state predicates replace polling sleeps; a separate 120-second hang watchdog remains. Delivery/refusal/debit assertions replace the 25-second host-performance assertion. Unique identities, directories and port-zero listeners were already present. |
| `node::tests::offline_fee_barrier_preserves_local_identity_and_storage` | The test constructed/dropped an extra node only to obtain its identity, then immediately reopened the same state-lock path. Derive the expected identity directly, so only the tested node acquires that lease. Use a unique backup path and an owned ephemeral HTTP 503 endpoint instead of fixed port 1. The original failing lock holder was not captured; descriptor inheritance during concurrent process creation remains a hypothesis, not a demonstrated asynchronous owner. |
| `password_fd_cli::local_owner_unavailable_verifier_refuses_start_without_writing_files` | A five-second exit deadline included process scheduling and Argon2 verification. Await child exit after password EOF. Keep the OS-assigned API port reserved until exit (the expected refusal precedes binding), removing bind/drop/rebind exposure. API/P2P cannot both be configured as port zero because existing config validation rejects equal ports. Each case already owned a unique directory. |
| `onchain_operations::disconnected_client_does_not_cancel_outcome_recording` | Five-second entry/completion deadlines and repeated HTTP replay while the SQLite writer was queued; repeated requests also consumed API rate limits. Await wallet entry, abort/await the HTTP request, drop router ownership and release dispatch. The last test-provider drop signals that all task/state owners finished, including the detached writer. Inspect the durable row once and reconstruct the API to verify replay without another wallet dispatch. A cancellation regression now fails an assertion rather than hanging in a polling loop. |

The adjacent sponsor preflight test uses the same new entry notification instead of its five-second polling deadline.

## Production seams requiring security review

1. `handlers/introduction.rs`: `UnixClock` and `IntroductionSettings.clock`, used for card issuance and verification. Default construction calls the original `SystemTime::now().duration_since(UNIX_EPOCH)` implementation and preserves its error. No request/config field can select a clock.
2. `handlers/sponsor.rs`: the four former direct wall-time reads (ledger observation, approval claim, status, funding request) use that per-instance clock. All comparisons, durable high-water marks, locking, authorization and payment logic are unchanged. Pre-dispatch reads remain fresh reads.
3. `konsensus-node/src/main.rs`: initialize the new field with its real-clock default.

`AdmissionQuotes::started_at_for_test` is `#[cfg(test)]` only. It is absent from production builds; the real restart quarantine and its separate explicit-time tests remain unchanged. The shared mock payment backend and all production timeouts are unchanged.

## Verification

The controlled expiry regression was run with the fixture clock present but production still reading wall time: it failed because the expired signed request paid. Wiring the reads made all 25 sponsor tests pass.

A deliberate temporary mutation replacing the detached on-chain writer with a directly awaited writer made `disconnected_client_does_not_cancel_outcome_recording` fail with `disconnect cancelled outcome recording`. The production implementation was restored afterward.

Run the repeatable proof with:

```sh
python3 scripts/test-timing-flakes-374.py --log-dir /private/tmp/issue374-finish-unrestricted-proof --runs 4 --load-runs 2
cargo clippy --workspace --all-targets -- -D warnings
```

The proof script runs serial full suites, unsets `RUST_TEST_THREADS`, validates all 28 named tests each run, stops at the first failure, and cleans up its load workers. The command above implements the revised four-additional-run request, with eight CPU workers for the first two runs; the script retains its original 30/10 defaults for separately requested longer proofs. A 30-minute suite watchdog bounds genuine hangs; it does not synchronize successful test paths. Raw logs, exact source patch, timestamps and log hashes accompany `results.json` in the selected log directory.

Final full-suite counts, individual test counts and Clippy results are recorded in `verification.md` and `verification.json`; compressed raw logs accompany the report.
