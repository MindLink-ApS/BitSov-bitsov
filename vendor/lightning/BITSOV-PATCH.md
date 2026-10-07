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

The issue #157 changes above do not change serialization formats. The offline
safety diagnostic below adds optional odd TLV 49 to `ChannelDetails`. No
restore/import support is added; stale SCB restore stays disabled.

Tests:
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib bitsov`
`cargo test --manifest-path vendor/lightning/Cargo.toml --lib test_closing_signed_reinit_timeout`

## Offline safety diagnostics (2026-10-07)

- `ln/channel_state.rs`: expose
  `ChannelDetails.counterparty_force_close_spend_delay`, backed by
  `holder_selected_contest_delay` (`our_to_self_delay`). This is the delay we
  impose on the counterparty's commitment, protecting our breach window; the
  existing `force_close_spend_delay` describes the opposite direction.
- Serialize the optional field as odd TLV 49. This is backward-compatible:
  older readers skip the unknown odd TLV and older records decode with `None`.
  TLV 49 is a local allocation, not an upstream reservation; check for an
  upstream TLV collision before upgrading or rebasing this patch.
- The companion ldk-node patch forwards this field and uses
  `record_lightning_sync` to capture the process-local, non-persisted
  `latest_lightning_wallet_sync` height/time checkpoint after successful sync.
  See `../ldk-node/BITSOV-PATCH.md` for the checkpoint lifecycle.

These additions are read-only diagnostics. No LDK channel, commitment, sync,
broadcast, or safety behaviour changes.
