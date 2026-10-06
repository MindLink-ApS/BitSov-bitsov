# BitSov pinned Lightning patch — issue #157

This directory is the crates.io **lightning 0.2.2** archive, SHA-256
`4c90397b635e3ece6b9a723fb470a46cb9b3592f217d72e40540a5fada00289d`
(the original root Cargo.lock checksum). The patch does not upgrade the pinned
LDK version. Original `Cargo.toml.orig` is retained. Upstream:
https://github.com/lightningdevkit/rust-lightning/tree/v0.2.2/lightning

Local changes (plus rustfmt on these files):

- `ln/channelmanager.rs`: one runtime-only atomic policy and its one-way setter
  `require_cooperative_close_consent()`. When set, skip **only**
  `timer_check_closing_negotiation_progress`, which otherwise force-closes
  cooperative negotiation after two timer ticks. All other timers, explicit
  force-close and protocol/chain safety processing remain unchanged. Defaults
  false on fresh construction and deserialization. The host must enable it
  before `Node::start` on every maintenance restart.
- `chain/channelmonitor.rs`: read-only `has_pending_events()` includes queued
  events and the in-progress event handler. Inspect after claimable balances and
  before the output consumer's tracked outputs, so a SpendableOutputs handoff
  cannot produce false migration completion. No event is drained/acknowledged.
- `ln/shutdown_tests.rs`: stalled negotiation still times out normally, but stays
  open without broadcast under the explicit-consent policy.
- `chain/chainmonitor.rs`: pending event visibility through queueing, processing,
  ReplayEvent, and acknowledgement.
- `Cargo.toml`: declare upstream cfg names for local linting.
- Whitespace-only cleanup of three archive lines in `ln/channel.rs`,
  `ln/monitor_tests.rs`, and `ln/reload_tests.rs` for `git diff --check`.
- Include standard MIT/Apache license texts and a standalone test lockfile using
  the workspace Bitcoin/Lightning-types versions.

No serialization format changes. No restore/import support. These APIs are used
only by the current-live-state migration path; stale SCB restore stays disabled.

Tests:
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib bitsov`
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib test_closing_signed_reinit_timeout`
