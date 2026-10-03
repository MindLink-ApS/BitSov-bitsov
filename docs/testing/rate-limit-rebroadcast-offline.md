# Rate-limit/rebroadcast offline verification

The initial implementation verification used `--offline` under macOS
`sandbox-exec -p '(version 1)(allow default)(deny network*)'`. This denies all
networking, including loopback and 127.0.0.1:3141. No live chain/relay, real funds,
or daemon fixtures were used. No dependencies were downloaded.

Commands (workspace lock and vendor lock are separate):

```sh
cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib
cargo test --offline --locked -p konsensus-core -p konsensus-lightning --lib
cargo test --offline --locked -p esplora-client --lib
cargo clippy --offline --locked -p konsensus-core -p konsensus-lightning -p esplora-client --all-targets -- -D warnings
cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib --tests
```

The full workspace library selection was attempted under network denial. Exactly
77 existing LNbits/LND fixtures failed when creating their disposable sockets;
each failure contained `PermissionDenied` or `Operation not permitted`. These are
not passes. Re-running with `--skip` for only the exact names below verifies the
remaining library tests. No source test was ignored or weakened to permit a pass.
New HTTP tests run against in-memory responses; retry tests use Tokio virtual time.
The vendor suite includes a real BDK-signed pending transaction and wallet reservation,
plus abort/restart, funding evidence, header, wallet deadline and settlement tests.
The separately patched Esplora library has no standalone unit tests; its transport
is verified through the LDK fixture suite.

The initial regressions failed before the fixes: immediate duplicate broadcast,
missing shared 429 cooldown, ghost commitment eligibility, and loss of interrupted
package ownership. Production assertions then passed. Live incident recovery is
not claimed. The logged commitment's identity remains unproven by the supplied log.

## Socket fixtures excluded from the second workspace library run

```text
lnbits_tests::tests::create_invoice_malformed_json_returns_backend_error
lnbits_tests::tests::create_invoice_999_msat_rejected
lnbits_tests::tests::create_invoice_exactly_1000_msat_succeeds
lnbits_tests::tests::create_invoice_auth_error
lnbits_tests::tests::create_invoice_5xx_returns_backend_error
lnbits_tests::tests::create_invoice_missing_payment_hash
lnbits_tests::tests::create_invoice_rejects_zero_amount
lnbits_tests::tests::get_balance
lnbits_tests::tests::create_invoice_zero_msat_rejected
lnbits_tests::tests::fresh_provider_is_payment_capable
lnbits_tests::tests::create_invoice_success
lnbits_tests::tests::get_balance_5xx_returns_backend_error
lnbits_tests::tests::get_balance_auth_error
lnbits_tests::tests::get_balance_malformed_json_returns_backend_error
lnbits_tests::tests::get_balance_missing_fields_returns_zero
lnbits_tests::tests::get_balance_negative_returns_zero
lnbits_tests::tests::get_balance_with_balance_field_instead_of_msat
lnbits_tests::tests::get_payment_status_expired
lnbits_tests::tests::get_payment_status_incoming_direction_from_positive_amount
lnbits_tests::tests::get_payment_status_malformed_json_returns_backend_error
lnbits_tests::tests::get_payment_status_no_details_returns_defaults
lnbits_tests::tests::get_payment_status_not_found
lnbits_tests::tests::get_payment_status_settled
lnbits_tests::tests::get_payment_status_zero_amount_is_incoming
lnbits_tests::tests::get_payment_status_outgoing_direction_from_negative_amount
lnbits_tests::tests::get_payment_status_pending
lnbits_tests::tests::is_available_returns_false_on_5xx
lnbits_tests::tests::list_payments_malformed_json_returns_backend_error
lnbits_tests::tests::is_available_returns_true
lnbits_tests::tests::list_payments_caps_at_100
lnbits_tests::tests::list_payments_returns_entries
lnbits_tests::tests::list_payments_empty
lnbits_tests::tests::list_payments_parses_direction_and_status
lnbits_tests::tests::list_payments_status_mapping
lnbits_tests::tests::pay_invoice_5xx_marks_payment_incapable
lnbits_tests::tests::pay_invoice_5xx_returns_backend_error
lnbits_tests::tests::pay_invoice_malformed_json_returns_backend_error
lnbits_tests::tests::probe_detects_unreachable_api
lnbits_tests::tests::probe_succeeds_with_real_funding_source
lnbits_tests::tests::probe_detects_voidwallet
lnbits_tests::tests::pay_invoice_success
lnbits_tests::tests::pay_invoice_auth_error
lnbits_tests::tests::successful_payment_clears_incapable_flag
lnbits_tests::tests::verify_payment_rejects_unsettled
lnbits_tests::tests::verify_payment_settled
lnbits_tests::tests::trailing_slash_in_url_works
lnd::tests::empty_balance_returns_zero
lnd::tests::garbage_json_returns_backend_error
lnd::tests::http_401_returns_auth_error
lnd::tests::get_node_pubkey_from_mock_lnd
lnd::tests::empty_channels_returns_empty_vec
lnd::tests::http_500_list_channels_returns_backend_error
lnd::tests::http_404_balance_returns_error
lnd::tests::http_500_marks_payment_incapable
lnd::tests::keysend_failure_returns_error
lnd::tests::keysend_invalid_hex_pubkey_returns_error
lnd::tests::keysend_success_returns_payment_details
lnd::tests::list_payments_empty_returns_empty_vec
lnd::tests::list_payments_limit_capped_at_100
lnd::tests::list_payments_returns_parsed_payments
lnd::tests::malformed_invoice_missing_r_hash
lnd::tests::mock_lnd_create_invoice
lnd::tests::malformed_invoice_missing_payment_request
lnd::tests::mock_lnd_get_balance
lnd::tests::mock_lnd_is_available
lnd::tests::mock_lnd_list_channels
lnd::tests::mock_lnd_probe_synced
lnd::tests::pay_invoice_empty_body_returns_error
lnd::tests::pay_invoice_mixed_garbage_finds_valid_line
lnd::tests::pay_invoice_error_response_returns_payment_failed
lnd::tests::pay_invoice_streaming_uses_final_result
lnd::tests::payment_status_not_found_in_either
lnd::tests::payment_status_falls_through_to_outgoing_payments
lnd::tests::payment_status_settled_invoice
lnd::tests::payment_status_zero_preimage_filtered
lnd::tests::probe_not_synced_marks_incapable
lnd::tests::verify_payment_settled_returns_ok
```

## Initial implementation results (1a6521b)

- Vendored LDK library: **81 passed**, zero failed or excluded.
- Core library: **354 passed**, zero failed or excluded.
- Lightning library: **158 passed**, zero failed in the second run; the **77**
  socket fixtures listed above were excluded after their denied-network failures.
- Patched Esplora library target: builds/passes with zero standalone unit tests;
  actual client behavior is covered by LDK's socket-free HTTP fixtures.
- Workspace/Core/Lightning/Esplora Clippy with `-D warnings`: passed.
- Vendored LDK Clippy (`--lib --tests`): completed with **281 warnings**, matching
  the prior vendor baseline's warning count; it is not claimed warning-clean.
- `git diff --check`: passed. No live-network validation was performed.

An independent read-only review found and prompted fixes for startup 429 retry
classification, reservation-lookup cooldown sharing, and aborted broadcast worker
retention. Subsequent Grok and Fable verdicts rejected the unbounded shared
cooldown; Grok also identified the incorrect funding-status endpoint. The fix
round below supersedes the initial review outcome.

Doctrine: 1, 2, 5 and 6 hold; 3 and 4 unchanged. No readiness or settlement rule
was relaxed, and no live incident resolution is asserted.


## Review fix round (3 October 2026)

The two supplied verdicts and the existing d9ef270 sanity-log item 22 were read
locally. No live backend checks were performed. The corrected fixtures first
failed on the old endpoint, unbounded header, and sequential broadcast worker.

Changes verified:

- Funding presence uses `get_tx_info`, where `/tx/{txid}` 404 is absent and a
  valid 200 transaction is present, including mempool transactions. The fixture
  reproduces `/status` 200 `{"confirmed":false}` alongside `/tx` 404 through
  `Node::funding_present`. #192 closed balances (`ldk.rs::funded_balances`) and
  reservation reconciliation/send verification (`onchain.rs::ChainVisibility`)
  both call that API; ghost eligibility uses the same chain-source method.
- Numeric 86400, maximum-u64 and future HTTP-date headers are capped at 300s.
  A POST is attempted by 300s even when another request refreshes the cooldown
  at second 299; that POST does not clear the newer GET cooldown.
- The real queue worker broadcasts a newly queued sweep while another package
  keeps returning 429. Shutdown/restart retains the parked package, and completing
  one concurrent package leaves the others' ownership and coalescing intact.

Final verification used `--offline --locked` under explicit macOS
`sandbox-exec -p '(version 1)(allow default)(deny network*)'`. Initial targeted
runs also used the environment's existing network-restricted sandbox. No network
connection was made, no dependency downloaded, and no daemon or live funds used.

```sh
cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib
cargo test --offline --locked -p konsensus-lightning -p konsensus-chain -p konsensus-api --lib --no-fail-fast
cargo clippy --offline --locked -p konsensus-lightning -p konsensus-chain -p konsensus-api --all-targets -- -D warnings
cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib --tests
```

The full crate run had **94 socket-fixture failures**, each containing
`PermissionDenied` / `Operation not permitted`: the 77 LNbits/LND names above
plus the 17 chain names below. The second crate run appended `-- --skip NAME`
for each of exactly those 94 names. These excluded tests are not claimed as
passes; no test was ignored or weakened in source.

| Target | Final result |
| --- | --- |
| Vendored LDK library | 87 passed, zero failed/excluded |
| konsensus-lightning library | 158 passed, 77 socket fixtures excluded |
| konsensus-chain library | 24 passed, 17 socket fixtures excluded |
| konsensus-api library | 216 passed, zero failed/excluded |
| Three workspace crates, Clippy, all targets, `-D warnings` | Passed |
| Vendored LDK Clippy, lib/tests | Passed with the existing 281-warning baseline |

The existing sqlx-postgres 0.8.0 future-incompatibility notice remains. Independent
read-only review of this fix found no blocker. No live incident resolution is
claimed. `git diff --check` passed.

Additional chain socket exclusions:

```text
esplora::tests::api_url_strips_trailing_api_suffix
esplora::tests::api_url_with_trailing_slash
esplora::tests::block_header_not_found_returns_error
esplora::tests::block_height_server_error_returns_backend_error
esplora::tests::confirmation_count_boundary
esplora::tests::empty_fee_estimates_returns_error
esplora::tests::estimate_fee_closest_target
esplora::tests::estimate_fee_exact_target
esplora::tests::fee_estimate_all_targets
esplora::tests::get_best_block_header
esplora::tests::get_block_header_existing
esplora::tests::get_block_height
esplora::tests::is_synced_returns_true
esplora::tests::tx_confirmed
esplora::tests::tx_insufficient_confirmations
esplora::tests::tx_lookup_not_found_returns_error
esplora::tests::tx_unconfirmed
```

Doctrine: 1 and 5 preserve settlement and self-custody with bounded independent
broadcast progress; 2 keeps chain evidence as chain evidence; 3 and 4 unchanged;
6 / P8 distinguishes offline evidence from live recovery. P7's liveness constraint
is enforced in code: once a transaction enters its broadcast wait, remote headers cannot extend it
beyond one capped cooldown; the existing HTTP-attempt deadline remains.
