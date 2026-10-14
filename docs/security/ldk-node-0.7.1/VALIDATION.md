# Validation

## Payment-status follow-up on `d23eb420`

The full vendored library suite passed **163/163**. The full
`konsensus-lightning` suite passed **392 tests**, with **0 failures and 2 existing
regtest ignores**, after permitting the local socket binds its fixtures require.
Both new vendor regressions failed against the unfixed handlers; the replay
control passed. The new application-boundary settlement regression also passed.
See [PAYMENT-STATUS.md](PAYMENT-STATUS.md) for commands, scope, audit and provenance,
and [payment-status-results.json](payment-status-results.json) for per-target
counts and the initial sandbox failures. The older results below remain an
unchanged record of the initial review.

## Initial backport validation

Environment: macOS arm64, Rust/Cargo 1.91.1. Tests run in the provided sandbox,
with two Cargo build jobs, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0`; build artifacts and raw logs are outside the
checkout under `/tmp/ldk-security-{target,vendor-target}` and
`/tmp/ldk-node-071-*.log`. No ignored tests or daemon integration features enabled.

## Focused and vendored checks

| Check | Observed result |
|---|---|
| Six new node regressions before fixes | 1 control passed; 5 failed for the expected vulnerabilities |
| `cargo test --locked --manifest-path vendor/ldk-node/Cargo.toml --lib security_071` after fixes | 6 passed, 0 failed |
| Final `cargo test --locked --manifest-path vendor/ldk-node/Cargo.toml --lib` | 160 passed, 0 failed, 0 ignored |
| Same entropy regression in an isolated Cargo fixture pinned to possiblyrandom 0.2.0, no explicit getrandom feature | Failed: returned all-zero buffer |
| Same isolated fixture pinned to 0.2.1 | 1 passed, 0 failed |
| `cargo test -p konsensus-crypto --locked --test possiblyrandom_regression` | 1 passed, 0 failed |
| `cargo tree --locked -e features -i possiblyrandom` | 0.2.1 selected, no explicit getrandom feature masking the bug |
| CI YAML parse and release dependency check | Passed; release-cli depends on ldk-node-security |
| `git diff --check 26e0b7e5` | Passed |
| Prior inventory versus base Git blobs | Every before-inventory hash matched |
| Byte preservation | 207 existing tracked vendor files unchanged; seven changed files listed in preservation.json; two new test files |

Red tests failed on observable behavior: the builder returned a node for Other;
keysend and BOLT12-offer receives created records despite a positive skim;
manual-claim receive emitted an application event for an even custom TLV;
the logger captured the send preimage. Control cases cover NotFound, corrupt
bytes, persisted manager height, zero skim, odd TLVs, and receipt/event preimages.
The final manager-restoration control asserts a serialized non-genesis height,
so a fresh replacement manager cannot accidentally satisfy it.

A first test compilation needed the current Lightning `PaymentSent` fields
`amount_msat` and `bolt12_invoice`. The first post-fix full vendor run passed 159
and failed the new logging test's cleanup because its synchronous
`Node::event_handled` API blocks inside a single-thread Tokio test runtime.
The fixture now awaits the existing event queue's async acknowledgement.
Neither fixture correction changed production behavior; the final full suite
passes 160/160. Existing JIT, stateless quote, wallet, watchtower, admission and
sync regressions all ran in that suite.

The event regressions inject events into the production handler on disposable,
unstarted nodes and inspect logs, payment records and the application queue.
They do not have a corresponding pending HTLC in ChannelManager, so they do not
verify network propagation of an HTLC failure or end-to-end settlement. The
failure call and `InvalidOnionPayload` reason were verified against upstream
source. No live funds, channels, RPCs or deployments were used.

## Workspace run

The requested `cargo test --workspace --locked` built the workspace, then exited
101 at `konsensus-api --test budget_grant_tests`: 139 passed and four failed
because the sandbox denied local socket binds with OS error 1,
`PermissionDenied: Operation not permitted`. Before that target, API unit tests
and the actual-fee, auth, balance-breakdown, bootstrap and box-transport suites
passed. This is not a green workspace run.

The failing tests in that first run were:

- `expiry::expiry_api_start_purges_before_binding_listener`
- `expiry::expiry_api_start_refuses_failed_cleanup_before_binding`
- `first_contact_grant::owner_socket_first_contact_checks_tuple_and_consumes_once`
- `sponsor::owner_socket_gift_checks_every_field_and_refuses_replay`

A follow-up `cargo test --workspace --locked --no-fail-fast` continues through
all targets so a sandbox-dependent API fixture cannot hide other crate results.
The results below describe that follow-up separately, without adding counts
from repeated focused/first runs.

Follow-up exit status: **101**, with **4187 passed, 388 failed, 7 ignored** across all 14 crates (including doc tests).

| Crate | Passed | Failed | Ignored |
|---|---:|---:|---:|
| konsensus-api | 1333 | 14 | 0 |
| konsensus-bsx | 89 | 0 | 0 |
| konsensus-chain | 82 | 32 | 1 |
| konsensus-core | 457 | 0 | 0 |
| konsensus-crypto | 272 | 0 | 0 |
| konsensus-fiat | 5 | 0 | 0 |
| konsensus-gossip | 30 | 0 | 0 |
| konsensus-lightning | 256 | 135 | 2 |
| konsensus-message | 245 | 75 | 0 |
| konsensus-node | 866 | 132 | 1 |
| konsensus-pricing | 135 | 0 | 1 |
| konsensus-recovery | 19 | 0 | 0 |
| konsensus-routing | 77 | 0 | 0 |
| konsensus-storage | 321 | 0 | 2 |

Every failed target and test name is retained in [workspace-results.json](workspace-results.json),
with per-test diagnostic categories. The failures report sandbox permission
denials, with four Mockito secondary errors reporting a closed server channel.
The owner-token script's generic exit failure was rerun separately and traced to
`PermissionError: [Errno 1] Operation not permitted` on its loopback-port probe.
Some node CLI tests also require PTY/process fixtures denied by this environment.
These failures are not reported as passes, and the suite was not rerun outside
the sandbox. Prior reviewed-base green results do not substitute for this run.

Independent read-only review found no outstanding production/test correctness
issues after adding the release job dependency. It separately verified all
before/after and preservation hashes. Tag signing trust, live funded/channel
behavior, and the hosted CI execution remain unverified as described in README.
