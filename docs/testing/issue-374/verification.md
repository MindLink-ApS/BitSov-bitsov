# Issue #374 verification

The four additional full-workspace runs passed at default concurrency; the first two used eight `yes > /dev/null` workers, all cleaned up afterward. Clippy passed with warnings denied.

**Correction to the earlier handoff:** the archived first batch has three clean suites and one interrupted suite. Run 4 passed all 28 focus tests, but `wire_invoice_limits` was terminated by SIGTERM and Cargo reported that target failed. Therefore the evidence is **seven clean full suites plus one interrupted suite**, with **8/8 passes for each of the 28 originally flaky tests**. No assertion failure is present in the interrupted run. No replacement suite was added beyond the four requested.

The initial sandbox-restricted attempt in this finishing session was stopped after local socket binds were denied. It is archived separately and excluded from this eight-run comparison.

| Run | CPU load | Full-workspace result | #374 tests |
| --- | --- | --- | --- |
| 1 | 8 workers | passed | 28/28 |
| 2 | 8 workers | passed | 28/28 |
| 3 | 8 workers | passed | 28/28 |
| 4 | 8 workers | interrupted | 28/28 |
| 5 | 8 workers | passed | 28/28 |
| 6 | 8 workers | passed | 28/28 |
| 7 | None added | passed | 28/28 |
| 8 | None added | passed | 28/28 |

Loaded runs 1–4 and 5–6 each recorded all eight workers alive at suite completion before cleanup. Run 4 recorded Cargo exit 101 from the SIGTERM-interrupted target; its metadata was finalized after the initial inspection in this session.

## Individual pass counts

| Test (libtest name) | Passes across runs 1–8 |
| --- | --- |
| `disconnected_client_does_not_cancel_outcome_recording` | 8/8 |
| `expired_candidate_resubmission_persists_terminal_expiry_even_on_refusal` | 8/8 |
| `local_owner_unavailable_verifier_refuses_start_without_writing_files` | 8/8 |
| `node::tests::offline_fee_barrier_preserves_local_identity_and_storage` | 8/8 |
| `reconciliation_cannot_release_a_live_dispatch_from_an_older_failed_record` | 8/8 |
| `regression_signed_request_expiry_is_enforced_at_approval` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::a_contact_without_a_budget_needs_the_one_time_confirmation_once` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::budgeted_contact_is_readmitted_from_the_budget_without_a_prompt` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_paired_send_cannot_add_unquoted_reconnection_debit` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_no_double_pay_on_retry_or_flap` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_readmission_refusal_carries_a_stable_reason` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_readmission_succeeds_when_quote_fits` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_refuses_before_payment_when_quote_does_not_fit` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_refuses_when_quoted_all_in_exceeds_grant_before_pay` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_refuses_with_no_quote` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_rejects_quote_from_prior_connection_generation` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::capped_reconnect_respects_paired_grant_contact_limit` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::failed_admission_releases_the_undispatched_message_reservation` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::failed_message_after_readmission_charges_admission_only_once` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::fresh_quote_is_reserved_into_the_grant_before_admission_pay` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::owner_readmission_preserves_zero_routing_fee_ceiling` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::paid_message_after_reconnect_is_delivered_not_silently_dropped` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::regression_readmission_respects_aggregate_grant_per_call_limit` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::regression_recovered_admission_emits_one_n2_event` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::repriced_readmission_error_reports_the_fee_ceilings_it_authorized` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::repriced_readmission_reports_the_fee_ceilings_it_authorized` | 8/8 |
| `session_handler::budgeted_reconnect_two_node::unknown_admission_keeps_only_its_own_reservation` | 8/8 |
| `sponsor::cancelled_owner_dispatch_retains_its_purse_reservation_for_restart` | 8/8 |

## Reproducibility

- Test command: `cargo test --workspace --no-fail-fast`; `RUST_TEST_THREADS` unset and no `--test-threads` override.
- Additional proof: `python3 scripts/test-timing-flakes-374.py --log-dir /private/tmp/issue374-finish-unrestricted-proof --runs 4 --load-runs 2` with local socket permissions.
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` exited 0. Existing dependency warnings and the `sqlx-postgres` future-incompatibility notice remain in the raw log; no workspace lint failure occurred.
- Base commit: `84ca3fd71b65a75cc472d8381720bceb7f555071`.
- Exact tested source patch SHA-256 (`git diff --binary -- crates`): `c9d02d3d3eaaea8566c5798f97a8982bddf3ddb1b8c8fd2a5f40b69a520af063`; identical across both batches.
- `source.diff.gz` preserves the exact tested source patch.
- `verification.json` records per-run summaries, per-test counts and SHA-256 hashes of the decompressed raw logs. `run-01.log.gz` through `run-08.log.gz`, `clippy.log.gz` and the excluded sandbox log preserve the underlying evidence.
- Production seam review is recorded in `docs/superpowers/plans/2026-10-22-isolate-timing-flakes-374.md`; independent security review remains outstanding.
